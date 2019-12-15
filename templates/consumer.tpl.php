<?php

$this->data['head'] = '<link rel="stylesheet" media="screen" type="text/css" href="'.
    SimpleSAML\Module::getModuleURL('openid/assets/css/openid.css').'" />';

$this->includeAtTemplateBase('includes/header.php');

?>

    <?php if (isset($this->data['error'])) { print "<div class=\"error\">".$this->data['error']."</div>"; } ?>

        <form method="get" action="consumer.php">
            <fieldset>
                <legend>OpenID Login</legend>

                Identity&nbsp;URL:
                <input type="hidden" name="action" value="verify" />
                <input id="openid-identifier" class="openid-identifier" type="text" name="openid_url" value="http://" />
                <input type="hidden" name="AuthState" value="<?php echo htmlspecialchars($this->data['AuthState']); ?>" />
                <input type="submit" value="Login with OpenID" />
            </fieldset>
        </form>

    <p style="margin-top: 2em">
       OpenID is a free and easy way to use a single digital identity across the Internet. Enter your OpenID identity URL in the box above to authenticate.
    </p>


<?php
$this->includeAtTemplateBase('includes/footer.php');
?>
