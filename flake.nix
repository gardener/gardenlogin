/*
SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/
{
  description = "Nix flake for gardenlogin";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.11";
  };

  outputs = {
    self,
    nixpkgs,
    ...
  }: let
    pname = "gardenlogin";

    # System types to support.
    supportedSystems = [
      "x86_64-linux"
      "x86_64-darwin"
      "aarch64-linux"
      "aarch64-darwin"
    ];

    # Helper function to generate an attrset '{ x86_64-linux = f "x86_64-linux"; ... }'.
    forAllSystems = nixpkgs.lib.genAttrs supportedSystems;

    # Nixpkgs instantiated for supported system types.
    nixpkgsFor = forAllSystems (system: import nixpkgs {inherit system;});
  in {
    # Provide some binary packages for selected system types.
    packages = forAllSystems (system: let
      pkgs = nixpkgsFor.${system};
      inherit (pkgs) stdenv lib;
    in {
      ${pname} = pkgs.buildGo120Module rec {
        inherit pname self;
        version = lib.fileContents ./VERSION;
        splitVersion = lib.versions.splitVersion version;
        major = if ((lib.elemAt splitVersion 0) == "v") then 
          lib.elemAt splitVersion 1
        else 
          lib.elemAt splitVersion 0;
        minor = if ((lib.elemAt splitVersion 0) == "v") then
          lib.elemAt splitVersion 2
        else
          lib.elemAt splitVersion 1;
        gitCommit = if (self ? rev) then
          self.rev
        else
          self.dirtyRev;
        state = if (self ? rev) then
          "clean"
        else
          "dirty";

        # This vendorHash represents a dervative of all go.mod dependancies and needs to be adjusted with every change
        vendorHash = "sha256-vmU0WrrEvfAHuWWrT9anZmQN+YNJIvrgjVUufws0X3s=";

        src = ./.;

        ldflags = [
          "-s"
          "-w"
          "-X k8s.io/component-base/version.gitMajor=${major}"
          "-X k8s.io/component-base/version.gitMinor=${minor}"
          "-X k8s.io/component-base/version.gitVersion=${version}"
          "-X k8s.io/component-base/version.gitTreeState=${state}"
          "-X k8s.io/component-base/version.gitCommit=${gitCommit}"
          "-X k8s.io/component-base/version/verflag.programName=${pname}"
          # "-X k8s.io/component-base/version.buildDate=1970-01-01T0:00:00+0000"
        ];

        CGO_ENABLED = 0;

        # subPackages = [
        # ];
        nativeBuildInputs = [pkgs.installShellFiles];

        postInstall = ''
          ln -s $out/bin/${pname} $out/bin/kubectl-${pname}
          installShellCompletion --cmd ${pname} \
              --zsh  <($out/bin/${pname} completion zsh) \
              --bash <($out/bin/${pname} completion bash) \
              --fish <($out/bin/${pname} completion fish)
        '';

        meta = with lib; {
          description = "gardenlogin is a kubectl credential plugin for Gardener";
          longDescription = ''
            gardenlogin is a kubectl credential plugin that facilitates Gardener managed cluster admin authentication.
            It is used to generate kubeconfigs for clusters with short-lived certificates, to access the cluster as cluster-admin.
          '';
          homepage = "https://github.com/gardener/gardenlogin";
          license = licenses.asl20;
          platforms = supportedSystems;
        };
      };
    });

    # Add dependencies that are only needed for development
    devShells = forAllSystems (system: let
      pkgs = nixpkgsFor.${system};
    in {
      default = pkgs.mkShell {
        buildInputs = with pkgs; [
          go_1_20
          gopls
          gotools
          go-tools
          gnumake
        ];
      };
    });

    # The default package for 'nix build'
    defaultPackage = forAllSystems (system: self.packages.${system}.${pname});
  };
}
