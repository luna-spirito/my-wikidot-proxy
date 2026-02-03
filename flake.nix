{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  };

  outputs =
    { self, nixpkgs, ... }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.rustPlatform.buildRustPackage {
            pname = "wikidot-proxy";
            version = "0.1.0";
            src = ./.;
            cargoLock.lockFile = ./Cargo.lock;
          };
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            buildInputs = with pkgs; [
              cargo
              rustc
              rust-analyzer
            ];
          };
        }
      );

      nixosModules.default =
        { settings, environmentFile }: # No, I don't like nixosModules. I'm a lambda guy.
        {
          config,
          pkgs,
          ...
        }:
        let
          cfg = config.services.wikidot-proxy;
          tomlFormat = pkgs.formats.toml { };
          configFile = tomlFormat.generate "wikidot-proxy.toml" settings;
        in
        {
          users.groups."wikidot-proxy" = { };
          users.users."wikidot-proxy" = {
            isSystemUser = true;
            group = "wikidot-proxy";
          };
          systemd.services.wikidot-proxy = {
            description = "Wikidot Mirror Reverse Proxy";
            after = [ "network.target" ];
            wantedBy = [ "multi-user.target" ];
            serviceConfig = {
              ExecStart = "${self.packages.${pkgs.system}.default}/bin/wikidot-proxy ${configFile}";
              EnvironmentFile = environmentFile;
              Restart = "always";
              User = "wikidot-proxy";
            };
          };
        };
    };
}
