<?php
/**
 * @file
 * ofed_uc_publication.rules_defaults.inc
 */

/**
 * Implements hook_default_rules_configuration().
 */
function ofed_uc_publication_default_rules_configuration() {
  $items = array();
  $items['uc_cart_send_email_to_the_dutch_administration'] = entity_import('rules_config', '{ "uc_cart_send_email_to_the_dutch_administration" : {
      "LABEL" : "Send email to the dutch administration",
      "PLUGIN" : "reaction rule",
      "OWNER" : "rules",
      "REQUIRES" : [ "rules", "uc_order", "uc_cart" ],
      "ON" : { "uc_checkout_complete" : [] },
      "IF" : [
        { "NOT data_is" : { "data" : [ "site:current-page:language" ], "value" : "fr" } }
      ],
      "DO" : [
        { "uc_order_email_invoice" : {
            "order" : [ "order" ],
            "from" : "IGVM - IEFH \\u003Cgelijkheid.manvrouw@igvm.belgie.be\\u003E",
            "addresses" : "gelijkheid.manvrouw@igvm.belgie.be",
            "subject" : "[store:name] - New Order",
            "template" : "admin",
            "view" : "admin-mail"
          }
        }
      ]
    }
  }');
  $items['uc_cart_send_email_to_the_french_administration'] = entity_import('rules_config', '{ "uc_cart_send_email_to_the_french_administration" : {
      "LABEL" : "Send email to the french administration",
      "PLUGIN" : "reaction rule",
      "OWNER" : "rules",
      "REQUIRES" : [ "rules", "uc_order", "uc_cart" ],
      "ON" : { "uc_checkout_complete" : [] },
      "IF" : [
        { "data_is" : { "data" : [ "site:current-page:language" ], "value" : "fr" } }
      ],
      "DO" : [
        { "uc_order_email_invoice" : {
            "order" : [ "order" ],
            "from" : "IGVM - IEFH \\u003Cegalite.hommesfemmes@iefh.belgique.be\\u003E",
            "addresses" : "egalite.hommesfemmes@iefh.belgique.be",
            "subject" : "[store:name] - New Order",
            "template" : "admin",
            "view" : "admin-mail"
          }
        }
      ]
    }
  }');
  return $items;
}
