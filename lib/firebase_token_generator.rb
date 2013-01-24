require "json"
require "base64"
require "openssl"

module Firebase

  class FirebaseTokenGenerator

    def initialize(secret)
      @secret = secret
    end

    def create_token(auth_data, options = {})
      claims = create_options_claims(options)
      claims[:v] = TOKEN_VERSION
      claims[:iat] = Time.now.to_i
      claims[:d] = auth_data
      encode_token(claims)
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

    def create_options_claims(options)
      opts = {}
      options.each do |key, value|
        if CLAIMS_MAP.include?(key.to_sym) then
          opts[key.to_sym] = value
        else
          raise ArgumentError, "#{key.to_s} is not a valid option"
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