# frozen_string_literal: true
# =============================================================================
# gen_upstream.rb <out-dir>
# =============================================================================
# Builds a tiny rubygems.org-shaped upstream tree for the
# rubygems-remote-bundler tier, with the real `gem` library of the client
# container, so every document is what a Bundler client expects:
#
#   gems/<name>-<ver>.gem                     real gems (Gem::Package.build)
#   quick/Marshal.4.8/<name>-<ver>.gemspec.rz Gem.deflate(Marshal.dump(spec))
#   specs.4.8.gz, latest_specs.4.8.gz,        gzipped Marshal 4.8 indexes
#   prerelease_specs.4.8.gz
#   versions, names, info/<name>              the Compact Index; each versions
#                                             line carries the MD5 of its
#                                             info/<name> body, which Bundler
#                                             checks
#   coded/info-dtfbundler-coded.gz            a gzip-coded info document the
#                                             oracle serves with
#                                             Content-Encoding: gzip
#
# dtfbundler-app 1.0.0 depends on dtfbundler-dep (~> 1.0), so resolving the
# app needs the dependency metadata of a second gem.
# =============================================================================
require 'rubygems/package'
require 'digest'
require 'fileutils'
require 'tmpdir'
require 'stringio'
require 'zlib'

out = File.expand_path(ARGV.fetch(0))
%w[gems quick/Marshal.4.8 info coded].each { |d| FileUtils.mkdir_p(File.join(out, d)) }

GEMS = [
  ['dtfbundler-dep', '1.0.0', []],
  ['dtfbundler-app', '0.9.0', [['dtfbundler-dep', '>= 1.0']]],
  ['dtfbundler-app', '1.0.0', [['dtfbundler-dep', '~> 1.0']]],
  ['dtfbundler-coded', '1.0.0', []]
].freeze

def gzip(bytes)
  io = StringIO.new(+'', 'wb')
  gz = Zlib::GzipWriter.new(io)
  gz.mtime = 0
  gz.write(bytes)
  gz.close
  io.string
end

built = []
GEMS.each do |name, version, deps|
  Dir.mktmpdir do |dir|
    Dir.chdir(dir) do
      lib = "lib/#{name.tr('-', '_')}.rb"
      FileUtils.mkdir_p('lib')
      File.write(lib, "module DtfBundler; VERSION = '#{version}'; end\n")
      spec = Gem::Specification.new do |s|
        s.name = name
        s.version = version
        s.summary = 'DTF fixture for artifact-keeper#5686'
        s.authors = ['dtf']
        s.license = 'MIT'
        s.files = [lib]
        s.required_ruby_version = '>= 2.0'
        deps.each { |dep, req| s.add_runtime_dependency(dep, req) }
      end
      file = Gem::Package.build(spec)
      FileUtils.cp(file, File.join(out, 'gems', file))
      bytes = File.binread(File.join(out, 'gems', file))
      File.binwrite(File.join(out, 'quick/Marshal.4.8', "#{spec.full_name}.gemspec.rz"),
                    Gem.deflate(Marshal.dump(spec)))
      built << [spec, Digest::SHA256.hexdigest(bytes)]
    end
  end
end

tuples = built.map { |spec, _| [spec.name, spec.version, 'ruby'] }
latest = tuples.group_by(&:first).map { |_, ts| ts.max_by { |t| t[1] } }
File.binwrite(File.join(out, 'specs.4.8.gz'), gzip(Marshal.dump(tuples)))
File.binwrite(File.join(out, 'latest_specs.4.8.gz'), gzip(Marshal.dump(latest)))
File.binwrite(File.join(out, 'prerelease_specs.4.8.gz'), gzip(Marshal.dump([])))

# Compact Index (https://guides.rubygems.org/rubygems-org-compact-index-api/).
info = Hash.new { |h, k| h[k] = +"---\n" }
built.each do |spec, sha|
  deps = spec.runtime_dependencies.map do |d|
    "#{d.name}:#{d.requirement.requirements.map { |op, v| "#{op} #{v}" }.join('&')}"
  end
  info[spec.name] << "#{spec.version} #{deps.join(',')}|checksum:#{sha},ruby:>= 2.0\n"
end
versions = +"created_at: 2026-11-13T00:00:00Z\n---\n"
info.keys.sort.each do |name|
  body = info[name]
  if name == 'dtfbundler-coded'
    File.binwrite(File.join(out, 'coded', "info-#{name}.gz"), gzip(body))
    next
  end
  File.binwrite(File.join(out, 'info', name), body)
  vs = built.select { |s, _| s.name == name }.map { |s, _| s.version.to_s }
  versions << "#{name} #{vs.join(',')} #{Digest::MD5.hexdigest(body)}\n"
end
File.binwrite(File.join(out, 'versions'), versions)
File.binwrite(File.join(out, 'names'), "---\n" + info.keys.sort.reject { |n| n == 'dtfbundler-coded' }.join("\n") + "\n")
puts "generated #{built.size} gems into #{out}"
