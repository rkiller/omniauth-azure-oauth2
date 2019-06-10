require 'omniauth/strategies/oauth2'
require 'jwt'
require 'openssl'
require 'securerandom'

module OmniAuth
  module Strategies
    class AzureOauth2 < OmniAuth::Strategies::OAuth2
      
      BASE_AZURE_URL = 'https://login.microsoftonline.com'

      option :name, 'azure_oauth2'
      option :tenant_provider, nil
      # AD resource identifier
      #option :resource, '00000002-0000-0000-c000-000000000000'
      option :version, 'v2.0/'
      option :scope, 'openid email profile' # 'https://graph.windows.net/user.read'
      option :response_type, 'id_token'
      option :provider_ignores_state, true # Needs to be set to true then check for nonce
      option :nonce, nil

      # tenant_provider must return client_id, client_secret and optionally tenant_id and base_azure_url
      args [:tenant_provider]

      def client
        provider = options.tenant_provider ? options.tenant_provider.new(self) : provider = options  # if pass has to config, get mapped right on to options

        options.client_id                       = provider.client_id
        options.client_secret                   = provider.client_secret
        options.tenant_id                       = provider.respond_to?(:tenant_id) ? provider.tenant_id : 'common'
        options.base_azure_url                  = provider.respond_to?(:base_azure_url) ? provider.base_azure_url : BASE_AZURE_URL
        options.authorize_params                = provider.authorize_params if provider.respond_to?(:authorize_params)
        options.authorize_params.response_type  = provider.response_type if provider.respond_to?(:response_type) && provider.response_type
        options.authorize_params.domain_hint    = provider.domain_hint if provider.respond_to?(:domain_hint) && provider.domain_hint
        options.authorize_params.prompt         = request.params['prompt'] if defined? request && request.params['prompt']
        options.authorize_params.scope          = provider.scope if provider.respond_to?(:scope) && provider.scope
        options.authorize_params.nonce          = new_nonce
        options.client_options.authorize_url    = "#{options.base_azure_url}/#{options.tenant_id}/oauth2/#{options.version}authorize"
        options.client_options.token_url        = "#{options.base_azure_url}/#{options.tenant_id}/oauth2/#{options.version}token"
        super
      end

      uid {
        raw_info['sub']
      }

      info do
        {
          name: raw_info['name'],
          nickname: raw_info['unique_name'],
          first_name: raw_info['given_name'],
          last_name: raw_info['family_name'],
          email: raw_info['email'] || raw_info['upn'],
          oid: raw_info['oid'],
          tid: raw_info['tid'],
          aud: raw_info['aud'],
          roles: raw_info['roles'],
          groups: raw_info['groups']
        }
      end

      #def token_params
      #  azure_resource = request.env['omniauth.params'] && request.env['omniauth.params']['azure_resource']
      #  super.merge(resource: azure_resource || options.resource)
      #end

      def callback_url
        full_host + script_name + callback_path
      end

      def raw_info
        # it's all here in JWT http://msdn.microsoft.com/en-us/library/azure/dn195587.aspx
        @raw_info ||= ::JWT.decode(access_token.token, nil, false).first
      end

      def callback_phase
        error = request.params['error_reason'] || request.params['error']
        fail(OAuthError, error) if error
        @session_state = request.params['session_state']
        @id_token = request.params['id_token']
        @code = request.params['code']
        @claims, @header = validate_and_parse_id_token(@id_token)
        validate_chash(@code, @claims, @header)
        super
      end

      # Verifies the signature of the id token as well as the exp, nbf, iat,
      # iss, and aud fields.
      #
      # See OpenId Connect Core 3.1.3.7 and 3.2.2.11.
      #
      # @return Claims, Header
      def validate_and_parse_id_token(id_token)
        # The second parameter is the public key to verify the signature.
        # However, that key is overridden by the value of the executed block
        # if one is present.
        #
        # If you're thinking that this looks ugly with the raw nil and boolean,
        # see https://github.com/jwt/ruby-jwt/issues/59.
        jwt_claims, jwt_header =
          JWT.decode(id_token, nil, true, verify_options) do |header|
            # There should always be one key from the discovery endpoint that
            # matches the id in the JWT header.
            x5c = (signing_keys.find do |key|
              key['kid'] == header['kid']
            end || {})['x5c']
            if x5c.nil? || x5c.empty?
              fail JWT::VerificationError,
                   'No keys from key endpoint match the id token'
            end
            # The key also contains other fields, such as n and e, that are
            # redundant. x5c is sufficient to verify the id token.
            OpenSSL::X509::Certificate.new(JWT.base64url_decode(x5c.first)).public_key
          end
        return jwt_claims, jwt_header if jwt_claims['nonce'] == read_nonce
        fail JWT::DecodeError, 'Returned nonce did not match.'
      end

      ##
      # Verifies that the c_hash the id token claims matches the authorization
      # code. See OpenId Connect Core 3.3.2.11.
      #
      # @param String code
      # @param Hash claims
      # @param Hash header
      def validate_chash(code, claims, header)
        # This maps RS256 -> sha256, ES384 -> sha384, etc.
        algorithm = (header['alg'] || 'RS256').sub(/RS|ES|HS/, 'sha')
        full_hash = OpenSSL::Digest.new(algorithm).digest code
        c_hash = JWT.base64url_encode full_hash[0..full_hash.length / 2 - 1]
        return if c_hash == claims['c_hash']
        fail JWT::VerificationError,
             'c_hash in id token does not match auth code.'
      end

      def new_nonce
        session['azure_oauth2.nonce'] = SecureRandom.uuid
      end

      def read_nonce
        session.delete('azure_oauth2.nonce')
      end


    end
  end
end
