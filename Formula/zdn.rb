class Zdn < Formula
  desc "Controller for isolated Zcash development networks (experimental preview)"
  homepage "https://github.com/jonwalch/zdn"
  url "https://github.com/jonwalch/zdn/releases/download/v0.1.0-preview.2/zdn-product-source-e4dbcae.tar.gz"
  version "0.1.0-preview.2"
  sha256 "4d13b892e07ecf22a8db70974f8c69df86cd7764d16812eda7b774371c10ea26"
  license any_of: ["MIT", "Apache-2.0"]

  depends_on "rust" => :build

  resource "required-notices" do
    url "https://github.com/jonwalch/zdn/releases/download/v0.1.0-preview.2/zdn-required-notices-preview.2.tar.gz"
    sha256 "c4fa717988bd5f296a650f81637d93f7e5f53c3d6d4103d473a7e7cd5a11f689"
  end

  def install
    system "cargo", "install", "--locked", "--path", ".", "--root", prefix
    pkgshare.install "Cargo.lock", "rust-toolchain.toml"
    doc.install "README.md", "LICENSE-MIT", "LICENSE-APACHE"
    (doc/"lightwallet-protocol").install "protocol/lightwallet-v0.5.0/README.md",
                                        "protocol/lightwallet-v0.5.0/LICENSE"
    resource("required-notices").stage { (pkgshare/"required-notices").install Dir["*"] }
  end

  def caveats
    <<~EOS
      Built locally from Preview 2 source e4dbcae; not the browser executable.
      This publisher tap is not reviewed or endorsed by Homebrew-core.
      AWS CLI/Session Manager and network launch inputs are separate prerequisites.
      Optional CLI payments require the separately installed ironwood-wallet.
      See https://github.com/jonwalch/zdn/blob/main/docs/install-source.md
    EOS
  end

  test do
    assert_match "zdn 0.1.0", shell_output("#{bin}/zdn --version")
    schema = JSON.parse(shell_output("#{bin}/zdn reference --schema"))
    assert_equal "zdn-command-reference/v1alpha1", schema.fetch("apiVersion")
    system bin/"zdn", "__runtime-capabilities", "--require", "zdn-build-export/v1alpha2"
    assert_match "unsupported",
shell_output("#{bin}/zdn __runtime-capabilities --require zdn-build-export/v999 2>&1", 1).downcase
  end
end
