# frozen_string_literal: true

require "minitest/autorun"
require "yaml"

class ReleaseVersionManifestTest < Minitest::Test
  ROOT = File.expand_path("..", __dir__)

  def test_release_manifest_matches_version_files_and_pinned_gemspecs
    manifest = release_manifest
    version = manifest.fetch("version")

    manifest.fetch("version_files").each do |path|
      full_path = File.join(ROOT, path)
      assert_path_exists full_path
      assert_equal version, File.read(full_path)[/VERSION\s*=\s*"([^"]+)"/, 1], "#{path} must match .release.yml"
    end

    manifest.fetch("literal_gemspec_versions").each do |path|
      full_path = File.join(ROOT, path)
      assert_path_exists full_path
      assert_equal version, File.read(full_path)[/spec\.version\s*=\s*"([^"]+)"/, 1], "#{path} spec.version must match .release.yml"
    end

    manifest.fetch("pinned_dependencies").each do |path, dependencies|
      full_path = File.join(ROOT, path)
      assert_path_exists full_path
      contents = File.read(full_path)

      dependencies.each do |dependency|
        assert_match(/spec\.add_dependency\s+"#{Regexp.escape(dependency)}",\s*"#{Regexp.escape(version)}"/, contents, "#{path} must pin #{dependency} to .release.yml")
      end
    end
  end

  def test_sync_versions_script_is_registered_as_rake_task
    rakefile = File.read(File.join(ROOT, "Rakefile"))

    assert_includes rakefile, "script/sync_versions.rb"
    assert_match(/task\s+"release:sync_versions"/, rakefile)
  end

  private

  def release_manifest
    YAML.safe_load_file(File.join(ROOT, ".release.yml"))
  end
end
