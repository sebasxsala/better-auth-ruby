# frozen_string_literal: true

module BetterAuth
  module SSO
    module SAML
      module Algorithms
        module_function

        SignatureAlgorithm = BetterAuth::Plugins::SSO_SAML_SIGNATURE_ALGORITHMS.merge(
          RSA_SHA1: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
          RSA_SHA256: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
          RSA_SHA384: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
          RSA_SHA512: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
          ECDSA_SHA256: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
          ECDSA_SHA384: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
          ECDSA_SHA512: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"
        ).freeze
        DigestAlgorithm = BetterAuth::Plugins::SSO_SAML_DIGEST_ALGORITHMS.merge(
          SHA1: "http://www.w3.org/2000/09/xmldsig#sha1",
          SHA256: "http://www.w3.org/2001/04/xmlenc#sha256",
          SHA384: "http://www.w3.org/2001/04/xmldsig-more#sha384",
          SHA512: "http://www.w3.org/2001/04/xmlenc#sha512"
        ).freeze
        KEY_ENCRYPTION_ALGORITHM = {
          RSA_1_5: "http://www.w3.org/2001/04/xmlenc#rsa-1_5",
          RSA_OAEP: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
          RSA_OAEP_SHA256: "http://www.w3.org/2009/xmlenc11#rsa-oaep"
        }.freeze
        DATA_ENCRYPTION_ALGORITHM = {
          TRIPLEDES_CBC: "http://www.w3.org/2001/04/xmlenc#tripledes-cbc",
          AES_128_CBC: "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
          AES_192_CBC: "http://www.w3.org/2001/04/xmlenc#aes192-cbc",
          AES_256_CBC: "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
          AES_128_GCM: "http://www.w3.org/2009/xmlenc11#aes128-gcm",
          AES_192_GCM: "http://www.w3.org/2009/xmlenc11#aes192-gcm",
          AES_256_GCM: "http://www.w3.org/2009/xmlenc11#aes256-gcm"
        }.freeze
        SecureSignatureAlgorithms = BetterAuth::Plugins::SSO_SAML_SECURE_SIGNATURE_ALGORITHMS
        SecureDigestAlgorithms = BetterAuth::Plugins::SSO_SAML_SECURE_DIGEST_ALGORITHMS

        def validate(xml, **options)
          if xml.is_a?(Hash)
            return validate_response(
              sig_alg: xml[:sig_alg] || xml[:sigAlg] || xml["sig_alg"] || xml["sigAlg"],
              saml_content: xml[:saml_content] || xml[:samlContent] || xml["saml_content"] || xml["samlContent"],
              **options
            )
          end

          BetterAuth::Plugins.sso_validate_saml_algorithms!(xml, normalize_options(options))
        end

        def validate_response(sig_alg: nil, saml_content: "", **options)
          xml = +""
          xml << "<ds:SignatureMethod Algorithm=\"#{sig_alg}\"/>" unless sig_alg.to_s.empty?
          xml << saml_content.to_s
          BetterAuth::Plugins.sso_validate_saml_algorithms!(xml, normalize_options(options))
        end

        def validate_config(config = {}, **options)
          config_keys = %i[signature_algorithm signatureAlgorithm digest_algorithm digestAlgorithm]
          inline_config = options.slice(*config_keys)
          normalized = BetterAuth::Plugins.normalize_hash((config || {}).merge(inline_config))
          options = options.except(*config_keys)
          xml = +""
          unless normalized[:signature_algorithm].to_s.empty?
            xml << "<ds:SignatureMethod Algorithm=\"#{normalized[:signature_algorithm]}\"/>"
          end
          unless normalized[:digest_algorithm].to_s.empty?
            xml << "<ds:DigestMethod Algorithm=\"#{normalized[:digest_algorithm]}\"/>"
          end
          BetterAuth::Plugins.sso_validate_saml_algorithms!(xml, normalize_options(options))
        end

        def normalize_signature(algorithm)
          BetterAuth::Plugins.sso_normalize_saml_signature_algorithm(algorithm)
        end

        def normalize_digest(algorithm)
          BetterAuth::Plugins.sso_normalize_saml_digest_algorithm(algorithm)
        end

        def normalize_options(options)
          normalized = BetterAuth::Plugins.normalize_hash(options || {})
          {
            on_deprecated: normalized[:on_deprecated],
            allowed_signature_algorithms: normalized[:allowed_signature_algorithms],
            allowed_digest_algorithms: normalized[:allowed_digest_algorithms],
            allowed_key_encryption_algorithms: normalized[:allowed_key_encryption_algorithms],
            allowed_data_encryption_algorithms: normalized[:allowed_data_encryption_algorithms]
          }.compact
        end
      end
    end
  end
end
