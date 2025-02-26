require 'omniauth/strategies/oauth2'
require 'jwt'

module OmniAuth
  module Strategies
    class AzureOauth2 < OmniAuth::Strategies::OAuth2
      
      BASE_AZURE_URL = 'https://login.microsoftonline.com'

      option :name, 'azure_oauth2'
      option :tenant_provider, nil
      # AD resource identifier
      option :resource, '00000002-0000-0000-c000-000000000000'
      option :version, '' #'v2.0/'
      option :scope, 'https://graph.windows.net/user.read' # 'openid email profile'
      #option :response_type, 'id_token'
      #option :nonce, nil

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
        #options.authorize_params.nonce          = new_nonce
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

      def new_nonce
        session['azure_oauth2.nonce'] = SecureRandom.uuid
      end

    end
  end
end
