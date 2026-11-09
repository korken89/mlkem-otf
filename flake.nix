{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };
  outputs =
    { nixpkgs, fenix, ... }:
    let
      pkgsFor =
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ fenix.overlays.default ];
          };
        in
        {
          inherit pkgs;

          # Fenix-managed Rust toolchain from rust-toolchain.toml.
          rustToolchain = pkgs.fenix.fromToolchainFile {
            dir = ./.;
            sha256 = "sha256-+xUr6Al1wZSqX8aEsq7DpuFOK4Ve/i+qTl+K5uWQ9GM=";
          };
        };

      systems = [
        "aarch64-linux"
        "x86_64-linux"
      ];

      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f (pkgsFor system));
    in
    {
      formatter = forAllSystems ({ pkgs, ... }: pkgs.nixfmt);

      devShells = forAllSystems (
        { pkgs, rustToolchain, ... }:
        {
          default = pkgs.mkShell {
            packages = [
              rustToolchain
              # Task runner (Makefile)
              pkgs.gnumake
              # Runs the measurements in qemu/ (qemu-system-arm)
              pkgs.qemu
              # Builds the QEMU instruction counter plugin
              pkgs.glib
              pkgs.pkg-config
              # llvm-objdump and llvm-size for the constant-time guard and code size
              pkgs.llvm
            ];
          };
        }
      );
    };
}
