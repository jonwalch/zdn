class Zdn < Formula
  desc "Controller for isolated Zcash development networks (experimental preview)"
  homepage "https://github.com/jonwalch/zdn"
  url "https://github.com/jonwalch/zdn/releases/download/v0.1.0-preview.4/zdn-product-source-3c136fb.tar.gz"
  version "0.1.0-preview.4"
  sha256 "efe868012fed69fa27814f9dcfe18ee536d9bd075044ba23a2bd3482559a4347"
  license any_of: ["MIT", "Apache-2.0"]

  depends_on "rust" => :build

  resource "required-notices" do
    url "https://github.com/jonwalch/zdn/releases/download/v0.1.0-preview.4/zdn-required-notices-preview.4.tar.gz"
    sha256 "d39883fb1b4a6a84c4a128541dddcb63f3cdf861d04fbf3772c88a15a7f07b3d"
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
      Built locally from Preview 4 source 3c136fb; no macOS release executable.
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
