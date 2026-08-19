{
  description = "Development environment for oidc-browser-login";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.rust-overlay = {
    url = "github:oxalica/rust-overlay";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  inputs.adocweave.url = "github:KeishiS/adocweave/88c98d22f0e43b23348e5281d65d4d02f3bba97a";

  outputs =
    {
      nixpkgs,
      rust-overlay,
      adocweave,
      ...
    }:
    let
      systems = [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];
      workspacePackage = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).workspace.package;
      forAllSystems = nixpkgs.lib.genAttrs systems;
      pkgsFor =
        system:
        import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };
    in
    {
      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          rustToolchain = pkgs.rust-bin.stable.${workspacePackage.rust-version}.default.override {
            extensions = [
              "clippy"
              "llvm-tools-preview"
              "rustfmt"
            ];
          };
        in
        {
          default = pkgs.mkShell {
            packages = [
              rustToolchain
              pkgs.actionlint
              pkgs.cargo-audit
              pkgs.cargo-llvm-cov
              pkgs.cargo-machete
              pkgs.cargo-make
              pkgs.jq
              pkgs.ripgrep
              adocweave.packages.${system}.default
            ];
          };
        }
      );
    };
}
