# frozen_string_literal: true

module BetterAuthExamples
  module EnvLoader
    module_function

    def load!
      root = File.expand_path("../../..", __dir__)
      load_file(File.join(root, ".env"))
      load_file(File.join(root, ".env.local"))
    end

    def load_file(path)
      return unless File.file?(path)

      File.readlines(path, chomp: true).each do |line|
        key, value = parse_line(line)
        next if key.nil? || value.to_s.empty? || ENV[key].to_s != ""

        ENV[key] = value
      end
    end

    def parse_line(line)
      stripped = line.to_s.strip
      return [nil, nil] if stripped.empty? || stripped.start_with?("#")

      key, value = stripped.split("=", 2)
      return [nil, nil] if key.to_s.empty? || value.nil?

      [key.strip, unquote(value.strip)]
    end

    def unquote(value)
      if (value.start_with?('"') && value.end_with?('"')) || (value.start_with?("'") && value.end_with?("'"))
        value[1...-1]
      else
        value
      end
    end
  end
end
