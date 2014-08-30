require "rubygems"
require "json"
require "base64"
require "openssl"
require "date"

module Firebase

  # This class handles generating signed authentication tokens for use with Firebase
  class FirebaseTokenGenerator

    # When creating an instance of the generator, you must provide your Firebase Application Secret
    def initialize(secret)
      if (!secret.is_a?(String))
        raise ArgumentError, "FirebaseTokenGenerator: secret must be a string"
      end
      @secret = secret
    end

    # Returns a signed Firebase Authentication Token
    # Takes the following arguments:
    # [auth_data] A hash of arbitrary data to be included in the token
    # [options] An optional hash of extra claims that may be included in the token. Allowed values are:
    #   [expires] Epoch time after which the token will no longer be valid
    #   [notBefore] Epoch time before which the token will not be valid
    #   [admin] If set to true, this client will bypass all security rules
    #   [debug] If set to true, this client will receive debug information about the security rules
    #   [simulate] (internal-only for now) Runs security rules but makes no data changes
    #
    # Throws ArgumentError if given invalid data or an invalid option
    # Throws RuntimeError if generated token is too long
    def create_token(auth_data, options = {})
      if (auth_data.nil? or auth_data.empty?) and (options.nil? or options.empty?)
        raise ArgumentError, "FirebaseTokenGenerator.create_token: data is empty and no options are set.  This token will have no effect on Firebase."
      end
      validate_auth_data(auth_data, (!options.nil? and options[:admin] == true))
      claims = create_options_claims(options)
      claims[:v] = TOKEN_VERSION
      claims[:iat] = Time.now.to_i
      claims[:d] = auth_data
      token = encode_token(claims)
      if (token.length > 1024)
        raise RuntimeError, "FirebaseTokenGenerator.create_token: generated token is too long."
      end
      token
    end

    private

    TOKEN_VERSION = 0

    TOKEN_SEP = "."

    CLAIMS_MAP = {
        :expires => :exp,
        :notBefore => :nbf,
        :admin => :admin,
        :debug => :debug,
        :simulate => :simulate
    }

    def validate_auth_data(auth_data, is_admin_token)
      if (!auth_data.nil? && !auth_data.is_a?(Hash))
        raise ArgumentError, "FirebaseTokenGenerator.create_token: auth data must be a hash"
      end
      contains_uid = (!auth_data.nil? and auth_data.has_key?(:uid))
      if ((!contains_uid and !is_admin_token) or (contains_uid and !auth_data[:uid].is_a?(String)))
        raise ArgumentError, "FirebaseTokenGenerator.create_token: auth data must contain a :uid key that must be a string."
      elsif (contains_uid and (auth_data[:uid].length > 256))
        raise ArgumentError, "FirebaseTokenGenerator.create_token: auth data must contain a :uid key that must not be longer than 256 bytes."
      end
    end

    def create_options_claims(options)
      opts = {}
      options.each do |key, value|
        if value.respond_to?(:strftime) then
          value = value.strftime("%s").to_i
        end
        if CLAIMS_MAP.include?(key.to_sym) then
          opts[CLAIMS_MAP[key.to_sym]] = value
        else
          raise ArgumentError, "FirebaseTokenGenerator.create_token: #{key.to_s} is not a valid option"
        end
      end
      opts
    end

    def encode_token(claims)
      encoded_header = encode_json({:typ => "JWT", :alg => "HS256"})
      encoded_claims = encode_json(claims)
      secure_bits = [encoded_header, encoded_claims].join(TOKEN_SEP)
      sig = sign(secure_bits)
      [encoded_header, encoded_claims, sig].join(TOKEN_SEP)
    end

    def encode_json(obj)
      encode(JSON.dump(obj))
    end

    def encode(s)
      Base64.urlsafe_encode64(s).gsub('=', '')
    end

    def sign(to_sign)
      encode(OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new, @secret, to_sign))
    end

  end

end