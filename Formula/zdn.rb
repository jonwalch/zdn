class Zdn < Formula
  desc "Controller for isolated Zcash development networks (experimental preview)"
  homepage "https://github.com/jonwalch/zdn"
  url "https://github.com/jonwalch/zdn/releases/download/v0.1.0-preview.3/zdn-product-source-fe2ccf3.tar.gz"
  version "0.1.0-preview.3"
  sha256 "5e7c167e690d42b1f16d46716cf6351e7a8d3a9cdbce59b3746ac5c98c272737"
  license any_of: ["MIT", "Apache-2.0"]

  depends_on "rust" => :build

  resource "required-notices" do
    url "https://github.com/jonwalch/zdn/releases/download/v0.1.0-preview.3/zdn-required-notices-preview.3.tar.gz"
    sha256 "00a1b43dd005ac6c73d5f5c65c531845d448d9d17aaa8416a5758235ea5c89fd"
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
      Built locally from Preview 3 source fe2ccf3; no macOS release executable.
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
