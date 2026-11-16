# Homebrew formula TEMPLATE for a tap (deep60/homebrew-tap). Not usable until 0.1.0 is on PyPI:
#   1. replace sha256 with the sdist's:  curl -sL <url> | shasum -a 256
#   2. generate every dependency's resource block:  brew update-python-resources ./dyepack.rb
#   3. brew install --build-from-source ./dyepack.rb && brew test dyepack && brew audit --new dyepack
# Dependencies include pydantic-core (Rust), hence the rust build dependency.
class Dyepack < Formula
  include Language::Python::Virtualenv

  desc "Red team for AI agents and MCP tools: leaks proven at a sink, not judged by an LLM"
  homepage "https://github.com/deep60/dyepack"
  url "https://files.pythonhosted.org/packages/source/d/dyepack/dyepack-0.1.0.tar.gz"
  sha256 "REPLACE_WITH_SDIST_SHA256"
  license "MIT"

  depends_on "rust" => :build
  depends_on "python@3.12"

  # resource blocks go here (step 2 above)

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/dyepack --version")
    system bin/"dyepack", "demo", "--out", testpath/"demo"
    assert_path_exists testpath/"demo/replay.html"
  end
end
