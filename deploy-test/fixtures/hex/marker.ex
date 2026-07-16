defmodule DtfMarker do
  @moduledoc """
  Marker module for the Artifact Keeper format-conformance hex leg.

  The `marker/0` string is grep-able so the conformance plugin can prove that a
  REAL `mix deps.get` fetched, verified, and unpacked this package's source from
  the AK hex registry (not merely that `/versions` listed it).
  """

  @marker "DTF-HEX-INSTALLED-1.0.0"

  @doc "Return the grep-able install marker."
  @spec marker() :: String.t()
  def marker, do: @marker
end
