module RedmineSslAuth
  module MonkeyPatches
    module AccountPatch
      def login_with_ssl_auth
        if !User.current.logged? and not params[:skip_ssl] and try_ssl_auth
          if @registered_on_the_fly
            redirect_to :controller => 'my', :action => 'account'
          else
            redirect_back_or_default :controller => 'my', :action => 'page'
          end
          return
        end

        login_without_ssl_auth
      end

      module InstanceMethods
        def try_ssl_auth
          session[:email] = request.env["SSL_CLIENT_S_DN_CN"]
          if session[:email]
            user = User.find_by_mail(session[:email]) || register_on_the_fly( session[:email] )
            unless user.nil?
              # Valid user
              return false if !user.active?
              user.update_attribute(:last_login_on, Time.now) if user && !user.new_record?
              self.logged_user = user
              return true
            end
          end
          false
        end

        def register_on_the_fly( email )
          username = email.split( '@' ).first
          user = User.new( :mail      => email,
                           :firstname => username,
                           :lastname  => username,
                           :language  => Setting.default_language )
          user.admin = false
          user.login = username
          user.password = username
          user.password_confirmation = username
          if user.save
            @registered_on_the_fly = true
            Mailer.deliver_account_information( user, username )
          end && user
        end
      end
      
      def self.included(base)
        base.class_eval do
          alias_method_chain :login, :ssl_auth
          include RedmineSslAuth::MonkeyPatches::AccountPatch::InstanceMethods
        end
      end      
    end
    AccountController.send(:include, AccountPatch)
  end
end