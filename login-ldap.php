<?php
namespace Grav\Plugin;

use Grav\Common\Plugin;
use Grav\Common\User\User;
use Grav\Common\Utils;
use Grav\Plugin\Login\Events\UserLoginEvent;
use Grav\Plugin\Login\Login;
use Symfony\Component\Ldap\Ldap;
use Symfony\Component\Ldap\Exception\ConnectionException;
use Symfony\Component\Yaml\Yaml;

/**
 * Class LoginLDAPPlugin
 * @package Grav\Plugin
 */
class LoginLDAPPlugin extends Plugin
{
    /**
     * @return array
     *
     * The getSubscribedEvents() gives the core a list of events
     *     that the plugin wants to listen to. The key of each
     *     array section is the event that the plugin listens to
     *     and the value (in the form of an array) contains the
     *     callable (or function) as well as the priority. The
     *     higher the number the higher the priority.
     */
    public static function getSubscribedEvents()
    {
        return [
            'onPluginsInitialized' => [
                ['autoload', 100000],
                ['onPluginsInitialized', 0]
            ],
            'onUserLoginAuthenticate'   => ['userLoginAuthenticate', 1000],
            'onUserLoginFailure'        => ['userLoginFailure', 0],
            'onUserLogin'               => ['userLogin', 0],
            'onUserLogout'              => ['userLogout', 0],
        ];
    }

    /**
     * [onPluginsInitialized:100000] Composer autoload.
     *
     * @return ClassLoader
     */
    public function autoload()
    {
        return require __DIR__ . '/vendor/autoload.php';
    }

    /**
     * Initialize the plugin
     */
    public function onPluginsInitialized()
    {
         
        // Check for PHP LDAP
        if (!function_exists('ldap_connect')) {
            throw new \RuntimeException('The PHP LDAP module needs to be installed and enabled');
        }

        // Check to ensure login plugin is enabled.
        if (!$this->grav['config']->get('plugins.login.enabled')) {
            throw new \RuntimeException('The Login plugin needs to be installed and enabled');
        }
    }

    public function userLoginAuthenticate(UserLoginEvent $event)
    {

       $this->grav['debugger']->addMessage("userLoginAuthenticate");

        $credentials = $event->getCredentials();

        // Get Proper username
        $user_dn            = $this->config->get('plugins.login-ldap.user_dn');
        $search_dn          = $this->config->get('plugins.login-ldap.search_dn');
        $group_dn           = $this->config->get('plugins.login-ldap.group_dn');
        $group_query        = $this->config->get('plugins.login-ldap.group_query');
        $group_indentifier  = $this->config->get('plugins.login-ldap.group_indentifier');

        $username   = str_replace('[username]', $credentials['username'], $user_dn);

        // Get Host info
        $host               = $this->config->get('plugins.login-ldap.host');
        $port               = $this->config->get('plugins.login-ldap.port');
        $version            = $this->config->get('plugins.login-ldap.version');
        $ssl                = $this->config->get('plugins.login-ldap.ssl');
        $start_tls          = $this->config->get('plugins.login-ldap.start_tls');
        $opt_referrals      = $this->config->get('plugins.login-ldap.opt_referrals');
        $blacklist          = $this->config->get('plugins.login-ldap.blacklist_ldap_fields', []);

        if (is_null($host)) {
            throw new ConnectionException('FATAL: LDAP host entry missing in plugin configuration...');
        }

        // Set Encryption
        if ((bool) $ssl) {
            $encryption = 'ssl';
        } elseif ((bool) $start_tls) {
            $encryption = 'tls';
        } else {
            $encryption = 'none';
        }

        try {
            /** @var Ldap $ldap */
            
            $ldap = Ldap::create('ext_ldap', array(
                'host' => $host,
                'port' => $port,
                'encryption' => $encryption,
                'options' => array(
                    'protocol_version' => $version,
                    'referrals' => (bool) $opt_referrals,
                ),
            ));

            // Map Info
            $map_username = $this->config->get('plugins.login-ldap.map_username');
            $map_fullname = $this->config->get('plugins.login-ldap.map_fullname');
            $map_email    = $this->config->get('plugins.login-ldap.map_email');
            $map_dn    = $this->config->get('plugins.login-ldap.map_dn');

            $this->grav['debugger']->addMessage($username);
            $this->grav['debugger']->addMessage($credentials['password']);
            
            if( $username == "" || $credentials['password'] == "")
            {
                $event->setStatus($event::AUTHENTICATION_FAILURE);
                $event->stopPropagation();
                return;
            }
            // Try to login via LDAP
            $this->grav['debugger']->addMessage('before binding');
            $ldap->bind($username, $credentials['password']);
            $this->grav['debugger']->addMessage('after binding');
            // Create Grav User
//            $grav_user = User::load(strtolower($username));
            $grav_user = User::load(strtolower($credentials['username']));

            // Set defaults with only thing we know... username provided
            $grav_user['login'] = $credentials['username'];
            $grav_user['fullname'] = $credentials['username'];
//            $this->grav['debugger']->addMessage( $username );
//            $this->grav['debugger']->addMessage( $grav_user['login'] );
//            $this->grav['debugger']->addMessage( $grav_user['fullname'] );
            $user_groups = [];

            // If search_dn is set we can try to get information from LDAP
            if ($search_dn) {
                $query_string = $map_username .'='. $credentials['username'];
                $query = $ldap->query($search_dn, $query_string);
//                 $this->grav['debugger']->addMessage("BEFORE QUERY");
                $results = $query->execute()->toArray();
//                $this->grav['debugger']->addMessage("AFTER QUERY");
//                $this->grav['debugger']->addMessage($results); 
                // Get LDAP Data
                if (empty($results)) {
                    $this->grav['log']->error('plugin.login-ldap: [401] user search for "' . $query_string . '" returned no user data');
                    $ldap_data =[];
                } else {
                    $ldap_data = array_shift($results)->getAttributes();
                }
                $userdata = [];

                $userdata['login'] = $this->getLDAPMappedItem($map_username, $ldap_data);
                
//                $this->grav['debugger']->addMessage($userdata['login']);
                
                $userdata['fullname'] = $this->getLDAPMappedItem($map_fullname, $ldap_data);
                $userdata['email'] = $this->getLDAPMappedItem($map_email, $ldap_data);
                $userdata['dn'] = $this->getLDAPMappedItem($map_dn, $ldap_data);
                $userdata['provider'] = 'ldap';
                
                // Get LDAP Data if required
                $arrayData = ['objectClass','memberOf','proxyAddresses','showInAddressBook','managedObjects','dSCorePropagationData', 'msExchUMDtmfMap'];
                if ($this->config->get('plugins.login-ldap.store_ldap_data', false)) {
                    foreach($ldap_data as $key => $data) {
                        if(in_array($key, $arrayData))
                           $userdata['ldap'][$key] = $data;    
                        else
                            $userdata['ldap'][$key] = array_shift($data);
                    }
                    unset($userdata['ldap']['userPassword']);
                }

                // Remove blacklisted fields
                foreach ($blacklist as $fieldName) {
                    if (isset($userdata['ldap'][$fieldName])) {
                        unset($userdata['ldap'][$fieldName]);
                    }
                }

                // Get Groups from 'memberOf' //BBA
                $userdata['groups'] = [];
                foreach ($userdata['ldap']['memberOf'] as $line) {
                     if ($this->config->get('plugins.login-ldap.store_ldap_data', false)) {
                        $g = $this->extractGroup($line);
                         //$this->grav['debugger']->addMessage($g);  
                         $userdata['groups'] = array_merge ($userdata['groups'] , $g);
                     }
                 }
                // Merge the LDAP user data with Grav user
                $grav_user->merge($userdata);
            }
            
            // Set Groups
            $current_groups = $grav_user->get('groups');
            $groups = $this->config->get('plugins.login-ldap.default_access_levels.groups', []);
            if (count($groups) > 0) {

                $data['groups'] = array_merge($groups, $current_groups);
                $grav_user->merge($data);
            }

            // Set Access
            $current_access = $grav_user->get('access');
            $access = $this->config->get('plugins.login-ldap.default_access_levels.access.site');

            if (!$current_access && $access) {
                if (count($access) > 0) {
                    $data['access']['site'] = $access;
                    $grav_user->merge($data);
                }
            }

            // Give Admin Access
            $admin_access = $this->config->get('plugins.login-ldap.default_access_levels.access.groups');
            if ($admin_access && count($user_groups) && strlen($admin_access) > 0) {
                $groups_access = Yaml::parse($admin_access);
                foreach ($groups_access as $key => $group_access) {
                    if (in_array($key, $user_groups)) {
                        $access_levels = Utils::arrayMergeRecursiveUnique($grav_user->access, $group_access);
                        $grav_user->merge(['access' => $access_levels]);
                    }
                }
            }

            // Optional save
            if ($this->config->get('plugins.login-ldap.save_grav_user', false)) {
                $grav_user->save();
            }

            $event->setUser($grav_user);

            $event->setStatus($event::AUTHENTICATION_SUCCESS);
            $event->stopPropagation();

            return;

        } catch (ConnectionException $e) {
            //dump("WTF");
//            $this->grav['debugger']->addMessage("AFTER QUERY");
            $message = $e->getMessage();
//            $message = "Wrong login and/or password";

            $this->grav['log']->error('plugin.login-ldap: ['. $e->getCode() . '] ' . $username . ' - ' . $message);

            // Just return so other authenticators can take a shot...
            if ($message = "Invalid credentials") {
                return;
            }

            $event->setStatus($event::AUTHENTICATION_FAILURE);
            $event->stopPropagation();

            return;
        }

    }

    public function userLoginFailure(UserLoginEvent $event)
    {
        // This gets fired if user fails to log in.
    }

    public function userLogin(UserLoginEvent $event)
    {
        // This gets fired if user successfully logs in.
        
    }

    public function userLogout(UserLoginEvent $event)
    {
        // This gets fired on user logout.
    }

    protected function getLDAPMappedItem($map, $ldap_data)
    {
        $item_bits = [];
        $map_bits = explode(' ', $map);
        foreach($map_bits as $bit) {
            if(isset($ldap_data[$bit])) {
            $item_bits[] = array_shift($ldap_data[$bit]);
            }
        }
        $item = implode(' ', $item_bits);
        return $item;
    }
    /**
     * Find CN 
     * @param type $line
     * @return array
     */
    protected function extractGroup($line)
    {
        $tmp = [];
        $t = explode(',', $line);
        foreach ($t as $v)
        {
            if(strrpos($v,'CN=') !== false)
            {
                array_push($tmp, substr($v,3));
            }
        }
        return $tmp;
    }
}
