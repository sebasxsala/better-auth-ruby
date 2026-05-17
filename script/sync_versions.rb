# frozen_string_literal: true

require "yaml"

ROOT = File.expand_path("..", __dir__)
MANIFEST_PATH = File.join(ROOT, ".release.yml")

def update_file(path)
  full_path = File.join(ROOT, path)
  original = File.read(full_path)
  updated = yield original

  File.write(full_path, updated) if updated != original
  updated != original
end

manifest = YAML.safe_load_file(MANIFEST_PATH)
version = manifest.fetch("version")
changed = []

manifest.fetch("version_files").each do |path|
  changed << path if update_file(path) { |contents| contents.gsub(/VERSION\s*=\s*"[^"]+"/, "VERSION = \"#{version}\"") }
end

manifest.fetch("literal_gemspec_versions").each do |path|
  changed << path if update_file(path) { |contents| contents.gsub(/spec\.version\s*=\s*"[^"]+"/, "spec.version = \"#{version}\"") }
end

manifest.fetch("pinned_dependencies").each do |path, dependencies|
  changed << path if update_file(path) do |contents|
    dependencies.reduce(contents) do |memo, dependency|
      memo.gsub(/(spec\.add_dependency\s+"#{Regexp.escape(dependency)}",\s*)"[^"]+"/, "\\1\"#{version}\"")
    end
  end
end

if changed.empty?
  puts "Versions already synced to #{version}."
else
  puts "Synced #{changed.uniq.size} files to #{version}:"
  changed.uniq.each { |path| puts "  #{path}" }
end
