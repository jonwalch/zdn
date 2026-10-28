class IronwoodWallet < Formula
  desc "Separate experimental Ironwood Testnet wallet backend for ZDN"
  homepage "https://github.com/jonwalch/zdn"
  url "https://github.com/jonwalch/zdn/releases/download/v0.1.0-preview.2/ironwood-wallet-source-70ccc7f.tar.gz"
  version "0.1.0-preview.2"
  sha256 "5fadd8187145d577d98a265dd50279483390e67b6617e50b1cabbb097d30a4d2"
  license any_of: ["MIT", "Apache-2.0"]

  depends_on "rust" => :build

  resource "required-notices" do
    url "https://github.com/jonwalch/zdn/releases/download/v0.1.0-preview.2/ironwood-wallet-required-notices-preview.2.tar.gz"
    sha256 "e195ddedd8928b40c6748370dafa0c03df045b46fa51e8630813aac67fe3650b"
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
      Built locally from standalone wallet source 70ccc7f (Common 3.0.0).
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
    assert_match "usage:", shell_output("#{bin}/ironwood-wallet not-a-command 2>&1", 1)
  end
end
