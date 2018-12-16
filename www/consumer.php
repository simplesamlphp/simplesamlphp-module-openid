<?php

// Find the authentication state
if (!array_key_exists('AuthState', $_REQUEST) || empty($_REQUEST['AuthState'])) {
    throw new \SimpleSAML\Error\BadRequest('Missing mandatory parameter: AuthState');
}

$authState = $_REQUEST['AuthState'];
$state = \SimpleSAML\Auth\State::loadState($authState, 'openid:init');
$sourceId = $state['openid:AuthId'];
$authSource = \SimpleSAML\Auth\Source::getById($sourceId);
if ($authSource === null) {
    throw new \SimpleSAML\Error\BadRequest('Invalid AuthId \''.$sourceId.'\' - not found.');
}

$error = null;
try {
    if (!empty($_GET['openid_url'])) {
        $authSource->doAuth($state, (string) $_GET['openid_url']);
    }
} catch (Exception $e) {
    $error = $e->getMessage();
}

$config = \SimpleSAML\Configuration::getInstance();
$t = new \SimpleSAML\XHTML\Template($config, 'openid:consumer.php', 'openid');
$t->data['error'] = $error;
$t->data['AuthState'] = $authState;
$t->show();
