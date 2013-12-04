<?php

/**
 * Implementation of hook_user_import_form_field_match().
 */
function field_user_import_form_field_match() {
  $options               = array();
  $supported_field_types = field_user_import_supported_fields();
  $fields_info           = field_info_instances('user', 'user');

  foreach ($fields_info as $field_name => $value) {
    $field_info = field_info_field($field_name);
    $type       = $field_info['type'];

    if (isset($supported_field_types[$type])) {
      $options['field'][$field_name] = $value['label'];
    }
    else {
      drupal_set_message(t('Field %field is not supported', array('%field' => $value['label'])), 'warning');
    }
  }

  return $options;
}

/**
 * Implementation of hook_user_import_data().
 */
function field_user_import_data($settings, $update_setting, $column_settings, $module, $field_id, $data, $column_id) {

  if ($module != 'field') return;

  $value = $data[$column_id];

  return $value;
}

/**
 * Implementation of hook_user_import_after_save().
 */
function field_user_import_after_save($settings, $account, $password, $fields, $updated, $update_setting_per_module) {

  $fields_data = isset($fields['field']) ? $fields['field'] : array();

  if (empty($fields_data)) return;

  $processors       = field_user_import_supported_fields();
  $delimiter        =  $settings['multi_value_delimiter'];
  $user_fields      = user_load($account->uid);
  $processed_fields = array();

  foreach ($fields_data as $field_name => $data) {
    $field_info         = field_info_field($field_name);
    $field_type         = $field_info['type'];
    $processor_function = $processors[$field_type]['save'];

    // Deal with multiple values.
    $values = explode($delimiter, $data[0]);

    // Use callback function to process info for field before saving.
    $processed_fields[$field_name] = $processor_function($user_fields, $field_name, $values);
  }

  if (!empty($processed_fields)) {
    user_save($account, $processed_fields);
  }

  return;
}

function field_user_import_default_field_processor($user_fields, $field_name, $values) {
  // @todo deal with multiple values
  // @todo deal with language
  // @todo deal with updating existing account

  $field = $user_fields->$field_name;

  for ($i = 0; $i < count($values); $i++) {
    if (!empty($values[$i])) {
      $field[LANGUAGE_NONE][$i]['value'] = $values[$i];
    }
  }

  return $field;
}

function field_user_import_supported_fields($output = 'all') {
  static $supported = array();

  if (empty($supported)) {
    $supported['text'] = array(
      'validate' => 'field_user_import_default_field_validator',
      'save'     => 'field_user_import_default_field_processor',
    );

    $supported['list_boolean'] = array(
      'validate' => 'field_user_import_default_field_validator',
      'save'     => 'field_user_import_default_field_processor',
    );

    $supported['number_decimal'] = array(
      'validate' => 'field_user_import_default_field_validator',
      'save'     => 'field_user_import_default_field_processor',
    );

    $supported['number_float'] = array(
      'validate' => 'field_user_import_default_field_validator',
      'save'     => 'field_user_import_default_field_processor',
    );

    $supported['number_integer'] = array(
      'validate' => 'field_user_import_default_field_validator',
      'save'     => 'field_user_import_default_field_processor',
    );

    $supported['list_float'] = array(
      'validate' => 'field_user_import_default_field_validator',
      'save'     => 'field_user_import_default_field_processor',
    );

    $supported['list_integer'] = array(
      'validate' => 'field_user_import_default_field_validator',
      'save'     => 'field_user_import_default_field_processor',
    );

    $supported['list_text'] = array(
      'validate' => 'field_user_import_default_field_validator',
      'save'     => 'field_user_import_default_field_processor',
    );

    // 'format'? 'safe_value'? - DONE
    $supported['text_long'] = array(
      'validate' => 'field_user_import_default_field_validator',
      'save'     => 'field_user_import_default_field_processor',
    );

    // 'format'? 'safe_value'? 'summary'? 'safe_summary'?
    $supported['text_with_summary'] = array(
      'validate' => 'field_user_import_default_field_validator',
      'save'     => 'field_user_import_default_field_processor',
    );

    $supported['taxonomy_term_reference'] = array(
      'validate' => 'field_user_import_default_field_validator',
      'save'     => 'field_user_import_default_field_processor',
    );

    /** Unsupported for the moment **/

//    $supported['file'] = array(
//      'validate' => 'field_user_import_default_field_validator',
//      'save' => 'field_user_import_default_field_processor',
//    );

//    $supported['image'] = array(
//      'validate' => 'field_user_import_default_field_validator',
//      'save' => 'field_user_import_default_field_processor',
//    );


    /** Not core - move to their own .inc files **/

//    $supported['datetime'] = array(
//      'validate' => 'field_user_import_default_field_validator',
//      'save' => 'field_user_import_default_field_processor',
//    );
//
//    $supported['date'] = array(
//      'validate' => 'field_user_import_default_field_validator',
//      'save' => 'field_user_import_default_field_processor',
//    );
//
//
//    $supported['datestamp'] = array(
//      'validate' => 'field_user_import_default_field_validator',
//      'save' => 'field_user_import_default_field_processor',
//    );

//    $supported['addressfield'] = array(
//      'validate' => 'field_user_import_default_field_validator',
//      'save' => 'field_user_import_default_field_processor',
//    );

    if (module_exists('fedict_beidmellon')) {
      $supported['fedict_fedid'] = array(
        'save'     => 'field_user_import_fedict_fedid_processor',
      );
    }

    // hook to add functions to this array.

  }

  return $supported;
}

/**
 * Copied from field_user_import_default_field_processor.
 */
function field_user_import_fedict_fedid_processor($user_fields, $field_name, $values) {
  try {
    $field = $user_fields->$field_name;

    // VALIDATE
    $fedid = $values[0];
    // Check for non allowed characters (ie. not numbers, spaces, dots or dashes)
    $allowed_characters_pattern = "/^[0-9A-z]+$/";

    if (preg_match($allowed_characters_pattern, $fedid) != 1) {
      throw new Exception(t("Non allowed character in FedID."));
    }
    else {
      // Length must be 40 characters.
      if (strlen($fedid) != 40) {
        throw new Exception(t("Length of the FedID is not 40 characters."));
      }
    }
    $query = new EntityFieldQuery;
    $query->entityCondition('entity_type', 'user')
    ->fieldCondition($field_name, 'fedict_fedid', $fedid)
    ->propertyCondition('uid', $user_fields->uid, '!=')
    ->count();
    $count = $query->execute();
    if ($count > 0) {
      throw new Exception(t('The submitted FedID is already being used by another account. It is not possible to have more than one account with the same FedID:'));
    }
    // SAVE
    $field[LANGUAGE_NONE][0]['fedict_fedid'] = _fedict_fedid_hash($fedid);
  }
  catch (Exception $e) {
    drupal_set_message(t('The user %uid has been saved but the FedID for this user has not been saved: ', array('%uid' => $user_fields->uid)) .  $e->getMessage(), 'warning');
  }

  return $field;
}
