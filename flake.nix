{
  description = "Flake for cd-webhooks-forwarder";

  outputs = { nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let pkgs = import nixpkgs { inherit system; };
      in
      {
        devShells = {
          default = with pkgs; mkShell {
            packages = [ protobuf ];
          };
        };
      });
}
