class IronwoodWallet < Formula
  desc "Separate experimental Ironwood Testnet wallet backend for ZDN"
  homepage "https://github.com/jonwalch/zdn"
  url "https://github.com/jonwalch/zdn/releases/download/v0.1.0-preview.4/ironwood-wallet-source-preview.4.tar.gz"
  version "0.1.0-preview.4"
  sha256 "c4f5dc330b81d43943f6d0b2526e8c0a4d7e4fe2ac2d7422dfc63e20762faf62"
  license any_of: ["MIT", "Apache-2.0"]

  depends_on "rust" => :build

  resource "required-notices" do
    url "https://github.com/jonwalch/zdn/releases/download/v0.1.0-preview.4/ironwood-wallet-required-notices-preview.4.tar.gz"
    sha256 "bcb80e704aac614e4526807dff344aa56199aebffdd941e8312c3dd5e3fd4fa6"
  end

  def install
    cd "experiments/ironwood-wallet" do
      system "cargo", "install", "--locked", "--path", ".", "--root", prefix
      pkgshare.install "Cargo.lock"
      doc.install "README.md"
    end
    pkgshare.install "SOURCE-PROVENANCE.json", "rust-toolchain.toml"
    doc.install "BUILDING.md", "LICENSE-MIT", "LICENSE-APACHE"
    resource("required-notices").stage { (pkgshare/"required-notices").install Dir["*"] }
  end

  def caveats
    <<~EOS
      Built locally from Preview 4 standalone wallet source 1906617 (Common 3.0.0).
      This publisher tap is not reviewed or endorsed by Homebrew-core.
      No --version command; use capabilities and record the executable SHA-256.
      Wallet keys/backups are plaintext secrets. No Mainnet or real funds.
      ZDN backend registration is a separate, explicit local configuration step.
      See https://github.com/jonwalch/zdn/blob/main/docs/install-source.md
    EOS
  end

  test do
    capabilities = JSON.parse(shell_output("#{bin}/ironwood-wallet capabilities"))
    assert_equal 1, capabilities.fetch("schema_version")
    assert_includes capabilities.fetch("capabilities"), "ironwood-wallet-state/v2"
    assert_includes capabilities.fetch("capabilities"), "ironwood-wallet-snapshot-payment/v2"
    assert_includes capabilities.fetch("capabilities"), "transparent-wallet-payments/v1"
    assert_includes capabilities.fetch("capabilities"), "transparent-wallet-state-observation/v1"
    assert_match "usage:", shell_output("#{bin}/ironwood-wallet not-a-command 2>&1", 1)
  end
end
