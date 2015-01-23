<?php
/**
 * @file
 * ofed_uc_publication.views_default.inc
 */

/**
 * Implements hook_views_default_views().
 */
function ofed_uc_publication_views_default_views() {
  $export = array();

  $view = new view();
  $view->name = 'publication_files';
  $view->description = '';
  $view->tag = 'default';
  $view->base_table = 'node';
  $view->human_name = 'Publication Files';
  $view->core = 7;
  $view->api_version = '3.0';
  $view->disabled = FALSE; /* Edit this to true to make a default view disabled initially */

  /* Display: Master */
  $handler = $view->new_display('default', 'Master', 'default');
  $handler->display->display_options['title'] = 'Publication Files';
  $handler->display->display_options['use_more_always'] = FALSE;
  $handler->display->display_options['access']['type'] = 'perm';
  $handler->display->display_options['cache']['type'] = 'none';
  $handler->display->display_options['query']['type'] = 'views_query';
  $handler->display->display_options['exposed_form']['type'] = 'basic';
  $handler->display->display_options['pager']['type'] = 'none';
  $handler->display->display_options['pager']['options']['offset'] = '0';
  $handler->display->display_options['style_plugin'] = 'default';
  $handler->display->display_options['row_plugin'] = 'fields';
  /* No results behavior: Global: Text area */
  $handler->display->display_options['empty']['area']['id'] = 'area';
  $handler->display->display_options['empty']['area']['table'] = 'views';
  $handler->display->display_options['empty']['area']['field'] = 'area';
  /* Relationship: Content translation: Source translation */
  $handler->display->display_options['relationships']['tnid']['id'] = 'tnid';
  $handler->display->display_options['relationships']['tnid']['table'] = 'node';
  $handler->display->display_options['relationships']['tnid']['field'] = 'tnid';
  $handler->display->display_options['relationships']['tnid']['required'] = TRUE;
  /* Relationship: Content translation: Translations */
  $handler->display->display_options['relationships']['translation_1']['id'] = 'translation_1';
  $handler->display->display_options['relationships']['translation_1']['table'] = 'node';
  $handler->display->display_options['relationships']['translation_1']['field'] = 'translation';
  $handler->display->display_options['relationships']['translation_1']['relationship'] = 'tnid';
  $handler->display->display_options['relationships']['translation_1']['required'] = TRUE;
  $handler->display->display_options['relationships']['translation_1']['language'] = 'all';
  /* Field: Content: File(s) */
  $handler->display->display_options['fields']['field_ofed_uc_publication_file']['id'] = 'field_ofed_uc_publication_file';
  $handler->display->display_options['fields']['field_ofed_uc_publication_file']['table'] = 'field_data_field_ofed_uc_publication_file';
  $handler->display->display_options['fields']['field_ofed_uc_publication_file']['field'] = 'field_ofed_uc_publication_file';
  $handler->display->display_options['fields']['field_ofed_uc_publication_file']['relationship'] = 'translation_1';
  $handler->display->display_options['fields']['field_ofed_uc_publication_file']['label'] = '';
  $handler->display->display_options['fields']['field_ofed_uc_publication_file']['element_label_colon'] = FALSE;
  $handler->display->display_options['fields']['field_ofed_uc_publication_file']['click_sort_column'] = 'fid';
  $handler->display->display_options['fields']['field_ofed_uc_publication_file']['delta_offset'] = '0';
  $handler->display->display_options['fields']['field_ofed_uc_publication_file']['multi_type'] = 'ul';
  /* Contextual filter: Content: Nid */
  $handler->display->display_options['arguments']['nid']['id'] = 'nid';
  $handler->display->display_options['arguments']['nid']['table'] = 'node';
  $handler->display->display_options['arguments']['nid']['field'] = 'nid';
  $handler->display->display_options['arguments']['nid']['relationship'] = 'translation';
  $handler->display->display_options['arguments']['nid']['default_action'] = 'default';
  $handler->display->display_options['arguments']['nid']['default_argument_type'] = 'raw';
  $handler->display->display_options['arguments']['nid']['default_argument_options']['index'] = '1';
  $handler->display->display_options['arguments']['nid']['summary']['number_of_records'] = '0';
  $handler->display->display_options['arguments']['nid']['summary']['format'] = 'default_summary';
  $handler->display->display_options['arguments']['nid']['summary_options']['items_per_page'] = '25';
  $handler->display->display_options['arguments']['nid']['specify_validation'] = TRUE;
  $handler->display->display_options['arguments']['nid']['validate']['type'] = 'node';
  $handler->display->display_options['arguments']['nid']['validate_options']['types'] = array(
    'ofed_uc_publication' => 'ofed_uc_publication',
  );
  $handler->display->display_options['arguments']['nid']['validate']['fail'] = 'empty';
  /* Filter criterion: Content: Published */
  $handler->display->display_options['filters']['status']['id'] = 'status';
  $handler->display->display_options['filters']['status']['table'] = 'node';
  $handler->display->display_options['filters']['status']['field'] = 'status';
  $handler->display->display_options['filters']['status']['value'] = 1;
  $handler->display->display_options['filters']['status']['group'] = 1;
  $handler->display->display_options['filters']['status']['expose']['operator'] = FALSE;
  /* Filter criterion: Content: Type */
  $handler->display->display_options['filters']['type']['id'] = 'type';
  $handler->display->display_options['filters']['type']['table'] = 'node';
  $handler->display->display_options['filters']['type']['field'] = 'type';
  $handler->display->display_options['filters']['type']['value'] = array(
    'ofed_uc_publication' => 'ofed_uc_publication',
  );

  /* Display: Current Publication */
  $handler = $view->new_display('attachment', 'Current Publication', 'attachment_4');
  $handler->display->display_options['display_description'] = 'The file of the current node';
  $handler->display->display_options['defaults']['relationships'] = FALSE;
  $handler->display->display_options['displays'] = array(
    'block' => 'block',
    'default' => 0,
  );

  /* Display: Current Language Main Node */
  $handler = $view->new_display('attachment', 'Current Language Main Node', 'attachment_5');
  $handler->display->display_options['display_description'] = 'show the main node of the current language, the one that have all the related items';
  $handler->display->display_options['pager']['type'] = 'none';
  $handler->display->display_options['pager']['options']['offset'] = '0';
  $handler->display->display_options['defaults']['relationships'] = FALSE;
  $handler->display->display_options['defaults']['arguments'] = FALSE;
  /* Contextual filter: Content: Related publications (field_ofed_uc_publication_relpub) */
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['id'] = 'field_ofed_uc_publication_relpub_target_id';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['table'] = 'field_data_field_ofed_uc_publication_relpub';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['field'] = 'field_ofed_uc_publication_relpub_target_id';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['default_action'] = 'default';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['default_argument_type'] = 'raw';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['default_argument_options']['index'] = '1';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['summary']['number_of_records'] = '0';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['summary']['format'] = 'default_summary';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['summary_options']['items_per_page'] = '25';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['specify_validation'] = TRUE;
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['validate']['type'] = 'node';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['validate_options']['types'] = array(
    'ofed_uc_publication' => 'ofed_uc_publication',
  );
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['validate']['fail'] = 'empty';
  $handler->display->display_options['defaults']['filter_groups'] = FALSE;
  $handler->display->display_options['defaults']['filters'] = FALSE;
  /* Filter criterion: Content: Published */
  $handler->display->display_options['filters']['status']['id'] = 'status';
  $handler->display->display_options['filters']['status']['table'] = 'node';
  $handler->display->display_options['filters']['status']['field'] = 'status';
  $handler->display->display_options['filters']['status']['value'] = 1;
  $handler->display->display_options['filters']['status']['group'] = 1;
  $handler->display->display_options['filters']['status']['expose']['operator'] = FALSE;
  /* Filter criterion: Content: Type */
  $handler->display->display_options['filters']['type']['id'] = 'type';
  $handler->display->display_options['filters']['type']['table'] = 'node';
  $handler->display->display_options['filters']['type']['field'] = 'type';
  $handler->display->display_options['filters']['type']['value'] = array(
    'ofed_uc_publication' => 'ofed_uc_publication',
  );
  /* Filter criterion: Content: Language */
  $handler->display->display_options['filters']['language']['id'] = 'language';
  $handler->display->display_options['filters']['language']['table'] = 'node';
  $handler->display->display_options['filters']['language']['field'] = 'language';
  $handler->display->display_options['filters']['language']['value'] = array(
    '***CURRENT_LANGUAGE***' => '***CURRENT_LANGUAGE***',
  );
  $handler->display->display_options['displays'] = array(
    'block' => 'block',
    'default' => 0,
  );

  /* Display: Translated Publications */
  $handler = $view->new_display('block', 'Translated Publications', 'block');
  $handler->display->display_options['display_description'] = 'when on a main node, of one of the site languages, show all the translations for that node';
  $handler->display->display_options['defaults']['empty'] = FALSE;
  /* No results behavior: Global: Text area */
  $handler->display->display_options['empty']['area']['id'] = 'area';
  $handler->display->display_options['empty']['area']['table'] = 'views';
  $handler->display->display_options['empty']['area']['field'] = 'area';
  $handler->display->display_options['empty']['area']['empty'] = TRUE;
  $handler->display->display_options['empty']['area']['format'] = 'full_html';
  $handler->display->display_options['defaults']['arguments'] = FALSE;
  /* Contextual filter: Content: Nid */
  $handler->display->display_options['arguments']['nid']['id'] = 'nid';
  $handler->display->display_options['arguments']['nid']['table'] = 'node';
  $handler->display->display_options['arguments']['nid']['field'] = 'nid';
  $handler->display->display_options['arguments']['nid']['default_action'] = 'default';
  $handler->display->display_options['arguments']['nid']['default_argument_type'] = 'raw';
  $handler->display->display_options['arguments']['nid']['default_argument_options']['index'] = '1';
  $handler->display->display_options['arguments']['nid']['summary']['number_of_records'] = '0';
  $handler->display->display_options['arguments']['nid']['summary']['format'] = 'default_summary';
  $handler->display->display_options['arguments']['nid']['summary_options']['items_per_page'] = '25';
  $handler->display->display_options['arguments']['nid']['specify_validation'] = TRUE;
  $handler->display->display_options['arguments']['nid']['validate']['type'] = 'node';
  $handler->display->display_options['arguments']['nid']['validate_options']['types'] = array(
    'ofed_uc_publication' => 'ofed_uc_publication',
  );
  $handler->display->display_options['arguments']['nid']['validate']['fail'] = 'empty';
  /* Contextual filter: Content: Nid */
  $handler->display->display_options['arguments']['nid_1']['id'] = 'nid_1';
  $handler->display->display_options['arguments']['nid_1']['table'] = 'node';
  $handler->display->display_options['arguments']['nid_1']['field'] = 'nid';
  $handler->display->display_options['arguments']['nid_1']['relationship'] = 'translation_1';
  $handler->display->display_options['arguments']['nid_1']['default_action'] = 'default';
  $handler->display->display_options['arguments']['nid_1']['default_argument_type'] = 'node';
  $handler->display->display_options['arguments']['nid_1']['summary']['number_of_records'] = '0';
  $handler->display->display_options['arguments']['nid_1']['summary']['format'] = 'default_summary';
  $handler->display->display_options['arguments']['nid_1']['summary_options']['items_per_page'] = '25';
  $handler->display->display_options['arguments']['nid_1']['not'] = TRUE;
  $handler->display->display_options['defaults']['filter_groups'] = FALSE;
  $handler->display->display_options['defaults']['filters'] = FALSE;
  /* Filter criterion: Content: Published */
  $handler->display->display_options['filters']['status']['id'] = 'status';
  $handler->display->display_options['filters']['status']['table'] = 'node';
  $handler->display->display_options['filters']['status']['field'] = 'status';
  $handler->display->display_options['filters']['status']['value'] = 1;
  $handler->display->display_options['filters']['status']['group'] = 1;
  $handler->display->display_options['filters']['status']['expose']['operator'] = FALSE;
  /* Filter criterion: Content: Type */
  $handler->display->display_options['filters']['type']['id'] = 'type';
  $handler->display->display_options['filters']['type']['table'] = 'node';
  $handler->display->display_options['filters']['type']['field'] = 'type';
  $handler->display->display_options['filters']['type']['value'] = array(
    'ofed_uc_publication' => 'ofed_uc_publication',
  );

  /* Display: Related publications */
  $handler = $view->new_display('attachment', 'Related publications', 'attachment_1');
  $handler->display->display_options['display_description'] = 'when on a main node, show all the related nodes of that node';
  $handler->display->display_options['pager']['type'] = 'none';
  $handler->display->display_options['pager']['options']['offset'] = '0';
  $handler->display->display_options['defaults']['relationships'] = FALSE;
  /* Relationship: Entity Reference: Referenced Entity */
  $handler->display->display_options['relationships']['field_ofed_uc_publication_relpub_target_id']['id'] = 'field_ofed_uc_publication_relpub_target_id';
  $handler->display->display_options['relationships']['field_ofed_uc_publication_relpub_target_id']['table'] = 'field_data_field_ofed_uc_publication_relpub';
  $handler->display->display_options['relationships']['field_ofed_uc_publication_relpub_target_id']['field'] = 'field_ofed_uc_publication_relpub_target_id';
  $handler->display->display_options['relationships']['field_ofed_uc_publication_relpub_target_id']['label'] = 'Entité Contenu réferencée par field_ofed_uc_publication_relpub';
  $handler->display->display_options['relationships']['field_ofed_uc_publication_relpub_target_id']['required'] = TRUE;
  $handler->display->display_options['defaults']['fields'] = FALSE;
  /* Field: Content: File(s) */
  $handler->display->display_options['fields']['field_ofed_uc_publication_file']['id'] = 'field_ofed_uc_publication_file';
  $handler->display->display_options['fields']['field_ofed_uc_publication_file']['table'] = 'field_data_field_ofed_uc_publication_file';
  $handler->display->display_options['fields']['field_ofed_uc_publication_file']['field'] = 'field_ofed_uc_publication_file';
  $handler->display->display_options['fields']['field_ofed_uc_publication_file']['relationship'] = 'field_ofed_uc_publication_relpub_target_id';
  $handler->display->display_options['fields']['field_ofed_uc_publication_file']['label'] = '';
  $handler->display->display_options['fields']['field_ofed_uc_publication_file']['element_label_colon'] = FALSE;
  $handler->display->display_options['fields']['field_ofed_uc_publication_file']['click_sort_column'] = 'fid';
  $handler->display->display_options['fields']['field_ofed_uc_publication_file']['delta_offset'] = '0';
  $handler->display->display_options['fields']['field_ofed_uc_publication_file']['multi_type'] = 'ul';
  $handler->display->display_options['defaults']['arguments'] = FALSE;
  /* Contextual filter: Content: Nid */
  $handler->display->display_options['arguments']['nid']['id'] = 'nid';
  $handler->display->display_options['arguments']['nid']['table'] = 'node';
  $handler->display->display_options['arguments']['nid']['field'] = 'nid';
  $handler->display->display_options['arguments']['nid']['default_action'] = 'default';
  $handler->display->display_options['arguments']['nid']['default_argument_type'] = 'node';
  $handler->display->display_options['arguments']['nid']['summary']['number_of_records'] = '0';
  $handler->display->display_options['arguments']['nid']['summary']['format'] = 'default_summary';
  $handler->display->display_options['arguments']['nid']['summary_options']['items_per_page'] = '25';
  $handler->display->display_options['arguments']['nid']['validate']['type'] = 'node';
  $handler->display->display_options['arguments']['nid']['validate_options']['types'] = array(
    'ofed_uc_publication' => 'ofed_uc_publication',
  );
  $handler->display->display_options['arguments']['nid']['validate']['fail'] = 'empty';
  $handler->display->display_options['displays'] = array(
    'block' => 'block',
    'default' => 0,
  );
  $handler->display->display_options['attachment_position'] = 'after';

  /* Display: Translated Publications - On a Related Node */
  $handler = $view->new_display('attachment', 'Translated Publications - On a Related Node', 'attachment_2');
  $handler->display->display_options['display_description'] = 'when seeing a related node, this will show the translated node of the "main" node of the current language';
  $handler->display->display_options['pager']['type'] = 'none';
  $handler->display->display_options['pager']['options']['offset'] = '0';
  $handler->display->display_options['defaults']['relationships'] = FALSE;
  /* Relationship: Content translation: Source translation */
  $handler->display->display_options['relationships']['tnid']['id'] = 'tnid';
  $handler->display->display_options['relationships']['tnid']['table'] = 'node';
  $handler->display->display_options['relationships']['tnid']['field'] = 'tnid';
  $handler->display->display_options['relationships']['tnid']['label'] = 'Source de la traduction';
  $handler->display->display_options['relationships']['tnid']['required'] = TRUE;
  /* Relationship: Content translation: Translations */
  $handler->display->display_options['relationships']['translation_1']['id'] = 'translation_1';
  $handler->display->display_options['relationships']['translation_1']['table'] = 'node';
  $handler->display->display_options['relationships']['translation_1']['field'] = 'translation';
  $handler->display->display_options['relationships']['translation_1']['relationship'] = 'tnid';
  $handler->display->display_options['relationships']['translation_1']['label'] = 'Traductions';
  $handler->display->display_options['relationships']['translation_1']['language'] = 'all';
  $handler->display->display_options['defaults']['fields'] = FALSE;
  /* Field: Content: File(s) */
  $handler->display->display_options['fields']['field_ofed_uc_publication_file']['id'] = 'field_ofed_uc_publication_file';
  $handler->display->display_options['fields']['field_ofed_uc_publication_file']['table'] = 'field_data_field_ofed_uc_publication_file';
  $handler->display->display_options['fields']['field_ofed_uc_publication_file']['field'] = 'field_ofed_uc_publication_file';
  $handler->display->display_options['fields']['field_ofed_uc_publication_file']['relationship'] = 'translation_1';
  $handler->display->display_options['fields']['field_ofed_uc_publication_file']['label'] = '';
  $handler->display->display_options['fields']['field_ofed_uc_publication_file']['element_label_colon'] = FALSE;
  $handler->display->display_options['fields']['field_ofed_uc_publication_file']['click_sort_column'] = 'fid';
  $handler->display->display_options['fields']['field_ofed_uc_publication_file']['delta_offset'] = '0';
  $handler->display->display_options['fields']['field_ofed_uc_publication_file']['multi_type'] = 'ul';
  $handler->display->display_options['defaults']['arguments'] = FALSE;
  /* Contextual filter: Content: Related publications (field_ofed_uc_publication_relpub) */
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['id'] = 'field_ofed_uc_publication_relpub_target_id';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['table'] = 'field_data_field_ofed_uc_publication_relpub';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['field'] = 'field_ofed_uc_publication_relpub_target_id';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['default_action'] = 'default';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['default_argument_type'] = 'raw';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['default_argument_options']['index'] = '1';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['summary']['number_of_records'] = '0';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['summary']['format'] = 'default_summary';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['summary_options']['items_per_page'] = '25';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['specify_validation'] = TRUE;
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['validate']['type'] = 'node';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['validate_options']['types'] = array(
    'ofed_uc_publication' => 'ofed_uc_publication',
  );
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['validate']['fail'] = 'empty';
  $handler->display->display_options['defaults']['filter_groups'] = FALSE;
  $handler->display->display_options['defaults']['filters'] = FALSE;
  /* Filter criterion: Content: Published */
  $handler->display->display_options['filters']['status']['id'] = 'status';
  $handler->display->display_options['filters']['status']['table'] = 'node';
  $handler->display->display_options['filters']['status']['field'] = 'status';
  $handler->display->display_options['filters']['status']['value'] = 1;
  $handler->display->display_options['filters']['status']['group'] = 1;
  $handler->display->display_options['filters']['status']['expose']['operator'] = FALSE;
  /* Filter criterion: Content: Type */
  $handler->display->display_options['filters']['type']['id'] = 'type';
  $handler->display->display_options['filters']['type']['table'] = 'node';
  $handler->display->display_options['filters']['type']['field'] = 'type';
  $handler->display->display_options['filters']['type']['value'] = array(
    'ofed_uc_publication' => 'ofed_uc_publication',
  );
  /* Filter criterion: Content: Language */
  $handler->display->display_options['filters']['language']['id'] = 'language';
  $handler->display->display_options['filters']['language']['table'] = 'node';
  $handler->display->display_options['filters']['language']['field'] = 'language';
  $handler->display->display_options['filters']['language']['relationship'] = 'translation_1';
  $handler->display->display_options['filters']['language']['operator'] = 'not in';
  $handler->display->display_options['filters']['language']['value'] = array(
    '***CURRENT_LANGUAGE***' => '***CURRENT_LANGUAGE***',
  );
  /* Filter criterion: Content: Language */
  $handler->display->display_options['filters']['language_1']['id'] = 'language_1';
  $handler->display->display_options['filters']['language_1']['table'] = 'node';
  $handler->display->display_options['filters']['language_1']['field'] = 'language';
  $handler->display->display_options['filters']['language_1']['operator'] = 'not in';
  $handler->display->display_options['filters']['language_1']['value'] = array(
    '***CURRENT_LANGUAGE***' => '***CURRENT_LANGUAGE***',
  );
  $handler->display->display_options['displays'] = array(
    'block' => 'block',
    'default' => 0,
  );
  $handler->display->display_options['attachment_position'] = 'after';

  /* Display: Related Publications - On a Related Node */
  $handler = $view->new_display('attachment', 'Related Publications - On a Related Node', 'attachment_3');
  $handler->display->display_options['display_description'] = 'when seeing a related node, this will show the related nodes of the "main" node of the current language';
  $handler->display->display_options['pager']['type'] = 'none';
  $handler->display->display_options['pager']['options']['offset'] = '0';
  $handler->display->display_options['defaults']['relationships'] = FALSE;
  /* Relationship: Entity Reference: Referencing entity */
  $handler->display->display_options['relationships']['reverse_field_ofed_uc_publication_relpub_node']['id'] = 'reverse_field_ofed_uc_publication_relpub_node';
  $handler->display->display_options['relationships']['reverse_field_ofed_uc_publication_relpub_node']['table'] = 'node';
  $handler->display->display_options['relationships']['reverse_field_ofed_uc_publication_relpub_node']['field'] = 'reverse_field_ofed_uc_publication_relpub_node';
  $handler->display->display_options['relationships']['reverse_field_ofed_uc_publication_relpub_node']['label'] = 'Contenu référençant Contenu depuis field_ofed_uc_publication_relpub';
  $handler->display->display_options['relationships']['reverse_field_ofed_uc_publication_relpub_node']['required'] = TRUE;
  /* Relationship: Entity Reference: Referenced Entity */
  $handler->display->display_options['relationships']['field_ofed_uc_publication_relpub_target_id']['id'] = 'field_ofed_uc_publication_relpub_target_id';
  $handler->display->display_options['relationships']['field_ofed_uc_publication_relpub_target_id']['table'] = 'field_data_field_ofed_uc_publication_relpub';
  $handler->display->display_options['relationships']['field_ofed_uc_publication_relpub_target_id']['field'] = 'field_ofed_uc_publication_relpub_target_id';
  $handler->display->display_options['relationships']['field_ofed_uc_publication_relpub_target_id']['relationship'] = 'reverse_field_ofed_uc_publication_relpub_node';
  $handler->display->display_options['relationships']['field_ofed_uc_publication_relpub_target_id']['required'] = TRUE;
  $handler->display->display_options['defaults']['fields'] = FALSE;
  /* Field: Content: File(s) */
  $handler->display->display_options['fields']['field_ofed_uc_publication_file']['id'] = 'field_ofed_uc_publication_file';
  $handler->display->display_options['fields']['field_ofed_uc_publication_file']['table'] = 'field_data_field_ofed_uc_publication_file';
  $handler->display->display_options['fields']['field_ofed_uc_publication_file']['field'] = 'field_ofed_uc_publication_file';
  $handler->display->display_options['fields']['field_ofed_uc_publication_file']['label'] = '';
  $handler->display->display_options['fields']['field_ofed_uc_publication_file']['element_label_colon'] = FALSE;
  $handler->display->display_options['fields']['field_ofed_uc_publication_file']['click_sort_column'] = 'fid';
  $handler->display->display_options['fields']['field_ofed_uc_publication_file']['delta_offset'] = '0';
  $handler->display->display_options['fields']['field_ofed_uc_publication_file']['multi_type'] = 'ul';
  $handler->display->display_options['defaults']['arguments'] = FALSE;
  /* Contextual filter: Content: Related publications (field_ofed_uc_publication_relpub) */
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['id'] = 'field_ofed_uc_publication_relpub_target_id';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['table'] = 'field_data_field_ofed_uc_publication_relpub';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['field'] = 'field_ofed_uc_publication_relpub_target_id';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['relationship'] = 'reverse_field_ofed_uc_publication_relpub_node';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['default_action'] = 'default';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['default_argument_type'] = 'raw';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['default_argument_options']['index'] = '1';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['summary']['number_of_records'] = '0';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['summary']['format'] = 'default_summary';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['summary_options']['items_per_page'] = '25';
  /* Contextual filter: Content: Nid */
  $handler->display->display_options['arguments']['nid']['id'] = 'nid';
  $handler->display->display_options['arguments']['nid']['table'] = 'node';
  $handler->display->display_options['arguments']['nid']['field'] = 'nid';
  $handler->display->display_options['arguments']['nid']['default_action'] = 'default';
  $handler->display->display_options['arguments']['nid']['default_argument_type'] = 'raw';
  $handler->display->display_options['arguments']['nid']['default_argument_options']['index'] = '1';
  $handler->display->display_options['arguments']['nid']['summary']['number_of_records'] = '0';
  $handler->display->display_options['arguments']['nid']['summary']['format'] = 'default_summary';
  $handler->display->display_options['arguments']['nid']['summary_options']['items_per_page'] = '25';
  $handler->display->display_options['arguments']['nid']['specify_validation'] = TRUE;
  $handler->display->display_options['arguments']['nid']['validate']['type'] = 'node';
  $handler->display->display_options['arguments']['nid']['validate_options']['types'] = array(
    'ofed_uc_publication' => 'ofed_uc_publication',
  );
  $handler->display->display_options['arguments']['nid']['validate']['fail'] = 'empty';
  $handler->display->display_options['arguments']['nid']['not'] = TRUE;
  $handler->display->display_options['defaults']['filter_groups'] = FALSE;
  $handler->display->display_options['defaults']['filters'] = FALSE;
  /* Filter criterion: Content: Published */
  $handler->display->display_options['filters']['status']['id'] = 'status';
  $handler->display->display_options['filters']['status']['table'] = 'node';
  $handler->display->display_options['filters']['status']['field'] = 'status';
  $handler->display->display_options['filters']['status']['value'] = 1;
  $handler->display->display_options['filters']['status']['group'] = 1;
  $handler->display->display_options['filters']['status']['expose']['operator'] = FALSE;
  /* Filter criterion: Content: Type */
  $handler->display->display_options['filters']['type']['id'] = 'type';
  $handler->display->display_options['filters']['type']['table'] = 'node';
  $handler->display->display_options['filters']['type']['field'] = 'type';
  $handler->display->display_options['filters']['type']['value'] = array(
    'ofed_uc_publication' => 'ofed_uc_publication',
  );
  /* Filter criterion: Content: Language */
  $handler->display->display_options['filters']['language']['id'] = 'language';
  $handler->display->display_options['filters']['language']['table'] = 'node';
  $handler->display->display_options['filters']['language']['field'] = 'language';
  $handler->display->display_options['filters']['language']['relationship'] = 'reverse_field_ofed_uc_publication_relpub_node';
  $handler->display->display_options['filters']['language']['value'] = array(
    '***CURRENT_LANGUAGE***' => '***CURRENT_LANGUAGE***',
  );
  $handler->display->display_options['displays'] = array(
    'block' => 'block',
    'default' => 0,
  );
  $handler->display->display_options['attachment_position'] = 'after';
  $translatables['publication_files'] = array(
    t('Master'),
    t('Publication Files'),
    t('more'),
    t('Apply'),
    t('Reset'),
    t('Sort by'),
    t('Asc'),
    t('Desc'),
    t('Source translation'),
    t('Translations'),
    t('All'),
    t('Current Publication'),
    t('The file of the current node'),
    t('Current Language Main Node'),
    t('show the main node of the current language, the one that have all the related items'),
    t('Translated Publications'),
    t('when on a main node, of one of the site languages, show all the translations for that node'),
    t('Related publications'),
    t('when on a main node, show all the related nodes of that node'),
    t('Entité Contenu réferencée par field_ofed_uc_publication_relpub'),
    t('Translated Publications - On a Related Node'),
    t('when seeing a related node, this will show the translated node of the "main" node of the current language'),
    t('Source de la traduction'),
    t('Traductions'),
    t('Related Publications - On a Related Node'),
    t('when seeing a related node, this will show the related nodes of the "main" node of the current language'),
    t('Contenu référençant Contenu depuis field_ofed_uc_publication_relpub'),
    t('Content entity referenced from field_ofed_uc_publication_relpub'),
  );
  $export['publication_files'] = $view;

  $view = new view();
  $view->name = 'publication_translations';
  $view->description = '';
  $view->tag = 'default';
  $view->base_table = 'node';
  $view->human_name = 'Publication translations';
  $view->core = 7;
  $view->api_version = '3.0';
  $view->disabled = FALSE; /* Edit this to true to make a default view disabled initially */

  /* Display: Master */
  $handler = $view->new_display('default', 'Master', 'default');
  $handler->display->display_options['title'] = 'Order';
  $handler->display->display_options['use_more_always'] = FALSE;
  $handler->display->display_options['access']['type'] = 'perm';
  $handler->display->display_options['cache']['type'] = 'none';
  $handler->display->display_options['query']['type'] = 'views_query';
  $handler->display->display_options['exposed_form']['type'] = 'basic';
  $handler->display->display_options['pager']['type'] = 'none';
  $handler->display->display_options['pager']['options']['offset'] = '0';
  $handler->display->display_options['style_plugin'] = 'default';
  $handler->display->display_options['row_plugin'] = 'fields';
  /* No results behavior: Global: Text area */
  $handler->display->display_options['empty']['area']['id'] = 'area';
  $handler->display->display_options['empty']['area']['table'] = 'views';
  $handler->display->display_options['empty']['area']['field'] = 'area';
  $handler->display->display_options['empty']['area']['empty'] = TRUE;
  $handler->display->display_options['empty']['area']['format'] = 'full_html';
  /* Relationship: Content translation: Source translation */
  $handler->display->display_options['relationships']['tnid']['id'] = 'tnid';
  $handler->display->display_options['relationships']['tnid']['table'] = 'node';
  $handler->display->display_options['relationships']['tnid']['field'] = 'tnid';
  /* Relationship: Content translation: Translations */
  $handler->display->display_options['relationships']['translation']['id'] = 'translation';
  $handler->display->display_options['relationships']['translation']['table'] = 'node';
  $handler->display->display_options['relationships']['translation']['field'] = 'translation';
  $handler->display->display_options['relationships']['translation']['relationship'] = 'tnid';
  $handler->display->display_options['relationships']['translation']['language'] = 'all';
  /* Field: Content: Nid */
  $handler->display->display_options['fields']['nid']['id'] = 'nid';
  $handler->display->display_options['fields']['nid']['table'] = 'node';
  $handler->display->display_options['fields']['nid']['field'] = 'nid';
  $handler->display->display_options['fields']['nid']['label'] = '';
  $handler->display->display_options['fields']['nid']['exclude'] = TRUE;
  $handler->display->display_options['fields']['nid']['element_label_colon'] = FALSE;
  /* Field: Content: Language */
  $handler->display->display_options['fields']['language']['id'] = 'language';
  $handler->display->display_options['fields']['language']['table'] = 'node';
  $handler->display->display_options['fields']['language']['field'] = 'language';
  $handler->display->display_options['fields']['language']['label'] = '';
  $handler->display->display_options['fields']['language']['exclude'] = TRUE;
  $handler->display->display_options['fields']['language']['alter']['alter_text'] = TRUE;
  $handler->display->display_options['fields']['language']['alter']['text'] = '([language])';
  $handler->display->display_options['fields']['language']['element_label_colon'] = FALSE;
  /* Field: Content: Title */
  $handler->display->display_options['fields']['title']['id'] = 'title';
  $handler->display->display_options['fields']['title']['table'] = 'node';
  $handler->display->display_options['fields']['title']['field'] = 'title';
  $handler->display->display_options['fields']['title']['label'] = '';
  $handler->display->display_options['fields']['title']['alter']['alter_text'] = TRUE;
  $handler->display->display_options['fields']['title']['alter']['text'] = '[title] [language]';
  $handler->display->display_options['fields']['title']['alter']['make_link'] = TRUE;
  $handler->display->display_options['fields']['title']['alter']['path'] = 'node/[nid]';
  $handler->display->display_options['fields']['title']['alter']['absolute'] = TRUE;
  $handler->display->display_options['fields']['title']['alter']['word_boundary'] = FALSE;
  $handler->display->display_options['fields']['title']['alter']['ellipsis'] = FALSE;
  $handler->display->display_options['fields']['title']['element_label_colon'] = FALSE;
  $handler->display->display_options['fields']['title']['link_to_node'] = FALSE;
  /* Field: Product: Add to cart form */
  $handler->display->display_options['fields']['addtocartlink']['id'] = 'addtocartlink';
  $handler->display->display_options['fields']['addtocartlink']['table'] = 'uc_products';
  $handler->display->display_options['fields']['addtocartlink']['field'] = 'addtocartlink';
  $handler->display->display_options['fields']['addtocartlink']['relationship'] = 'translation';
  $handler->display->display_options['fields']['addtocartlink']['label'] = '';
  $handler->display->display_options['fields']['addtocartlink']['element_label_colon'] = FALSE;
  /* Contextual filter: Content: Nid */
  $handler->display->display_options['arguments']['nid_1']['id'] = 'nid_1';
  $handler->display->display_options['arguments']['nid_1']['table'] = 'node';
  $handler->display->display_options['arguments']['nid_1']['field'] = 'nid';
  $handler->display->display_options['arguments']['nid_1']['relationship'] = 'translation_1';
  $handler->display->display_options['arguments']['nid_1']['default_action'] = 'default';
  $handler->display->display_options['arguments']['nid_1']['default_argument_type'] = 'node';
  $handler->display->display_options['arguments']['nid_1']['summary']['number_of_records'] = '0';
  $handler->display->display_options['arguments']['nid_1']['summary']['format'] = 'default_summary';
  $handler->display->display_options['arguments']['nid_1']['summary_options']['items_per_page'] = '25';
  /* Filter criterion: Content: Published */
  $handler->display->display_options['filters']['status']['id'] = 'status';
  $handler->display->display_options['filters']['status']['table'] = 'node';
  $handler->display->display_options['filters']['status']['field'] = 'status';
  $handler->display->display_options['filters']['status']['value'] = 1;
  $handler->display->display_options['filters']['status']['group'] = 1;
  $handler->display->display_options['filters']['status']['expose']['operator'] = FALSE;
  /* Filter criterion: Content: Type */
  $handler->display->display_options['filters']['type']['id'] = 'type';
  $handler->display->display_options['filters']['type']['table'] = 'node';
  $handler->display->display_options['filters']['type']['field'] = 'type';
  $handler->display->display_options['filters']['type']['value'] = array(
    'ofed_uc_publication' => 'ofed_uc_publication',
  );

  /* Display: Current Publication */
  $handler = $view->new_display('attachment', 'Current Publication', 'attachment_4');
  $handler->display->display_options['display_description'] = 'The link/form to the current node';
  $handler->display->display_options['pager']['type'] = 'none';
  $handler->display->display_options['pager']['options']['offset'] = '0';
  $handler->display->display_options['defaults']['relationships'] = FALSE;
  $handler->display->display_options['displays'] = array(
    'publication_languages' => 'publication_languages',
    'default' => 0,
  );

  /* Display: Current Language Main Node */
  $handler = $view->new_display('attachment', 'Current Language Main Node', 'attachment_5');
  $handler->display->display_options['display_description'] = 'show the main node of the current language, the one that have all the related items';
  $handler->display->display_options['pager']['type'] = 'some';
  $handler->display->display_options['defaults']['relationships'] = FALSE;
  $handler->display->display_options['defaults']['arguments'] = FALSE;
  /* Contextual filter: Content: Related publications (field_ofed_uc_publication_relpub) */
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['id'] = 'field_ofed_uc_publication_relpub_target_id';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['table'] = 'field_data_field_ofed_uc_publication_relpub';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['field'] = 'field_ofed_uc_publication_relpub_target_id';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['default_action'] = 'default';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['default_argument_type'] = 'raw';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['default_argument_options']['index'] = '1';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['summary']['number_of_records'] = '0';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['summary']['format'] = 'default_summary';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['summary_options']['items_per_page'] = '25';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['specify_validation'] = TRUE;
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['validate']['type'] = 'node';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['validate_options']['types'] = array(
    'ofed_uc_publication' => 'ofed_uc_publication',
  );
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['validate']['fail'] = 'empty';
  $handler->display->display_options['defaults']['filter_groups'] = FALSE;
  $handler->display->display_options['defaults']['filters'] = FALSE;
  /* Filter criterion: Content: Published */
  $handler->display->display_options['filters']['status']['id'] = 'status';
  $handler->display->display_options['filters']['status']['table'] = 'node';
  $handler->display->display_options['filters']['status']['field'] = 'status';
  $handler->display->display_options['filters']['status']['value'] = 1;
  $handler->display->display_options['filters']['status']['group'] = 1;
  $handler->display->display_options['filters']['status']['expose']['operator'] = FALSE;
  /* Filter criterion: Content: Type */
  $handler->display->display_options['filters']['type']['id'] = 'type';
  $handler->display->display_options['filters']['type']['table'] = 'node';
  $handler->display->display_options['filters']['type']['field'] = 'type';
  $handler->display->display_options['filters']['type']['value'] = array(
    'ofed_uc_publication' => 'ofed_uc_publication',
  );
  /* Filter criterion: Content: Language */
  $handler->display->display_options['filters']['language']['id'] = 'language';
  $handler->display->display_options['filters']['language']['table'] = 'node';
  $handler->display->display_options['filters']['language']['field'] = 'language';
  $handler->display->display_options['filters']['language']['value'] = array(
    '***CURRENT_LANGUAGE***' => '***CURRENT_LANGUAGE***',
  );
  $handler->display->display_options['displays'] = array(
    'publication_languages' => 'publication_languages',
    'default' => 0,
  );

  /* Display: Translated Publications */
  $handler = $view->new_display('block', 'Translated Publications', 'publication_languages');
  $handler->display->display_options['display_description'] = 'when on a main node, of one of the site languages, show all the translations for that node';
  $handler->display->display_options['defaults']['relationships'] = FALSE;
  /* Relationship: Content translation: Source translation */
  $handler->display->display_options['relationships']['tnid']['id'] = 'tnid';
  $handler->display->display_options['relationships']['tnid']['table'] = 'node';
  $handler->display->display_options['relationships']['tnid']['field'] = 'tnid';
  $handler->display->display_options['relationships']['tnid']['required'] = TRUE;
  /* Relationship: Content translation: Translations */
  $handler->display->display_options['relationships']['translation']['id'] = 'translation';
  $handler->display->display_options['relationships']['translation']['table'] = 'node';
  $handler->display->display_options['relationships']['translation']['field'] = 'translation';
  $handler->display->display_options['relationships']['translation']['relationship'] = 'tnid';
  $handler->display->display_options['relationships']['translation']['language'] = 'all';
  $handler->display->display_options['defaults']['fields'] = FALSE;
  /* Field: Content: Nid */
  $handler->display->display_options['fields']['nid']['id'] = 'nid';
  $handler->display->display_options['fields']['nid']['table'] = 'node';
  $handler->display->display_options['fields']['nid']['field'] = 'nid';
  $handler->display->display_options['fields']['nid']['relationship'] = 'translation';
  $handler->display->display_options['fields']['nid']['label'] = '';
  $handler->display->display_options['fields']['nid']['exclude'] = TRUE;
  $handler->display->display_options['fields']['nid']['element_label_colon'] = FALSE;
  /* Field: Content: Language */
  $handler->display->display_options['fields']['language']['id'] = 'language';
  $handler->display->display_options['fields']['language']['table'] = 'node';
  $handler->display->display_options['fields']['language']['field'] = 'language';
  $handler->display->display_options['fields']['language']['relationship'] = 'translation';
  $handler->display->display_options['fields']['language']['label'] = '';
  $handler->display->display_options['fields']['language']['exclude'] = TRUE;
  $handler->display->display_options['fields']['language']['alter']['alter_text'] = TRUE;
  $handler->display->display_options['fields']['language']['alter']['text'] = '([language])';
  $handler->display->display_options['fields']['language']['element_label_colon'] = FALSE;
  /* Field: Content: Title */
  $handler->display->display_options['fields']['title']['id'] = 'title';
  $handler->display->display_options['fields']['title']['table'] = 'node';
  $handler->display->display_options['fields']['title']['field'] = 'title';
  $handler->display->display_options['fields']['title']['relationship'] = 'translation';
  $handler->display->display_options['fields']['title']['label'] = '';
  $handler->display->display_options['fields']['title']['alter']['alter_text'] = TRUE;
  $handler->display->display_options['fields']['title']['alter']['text'] = '[title] [language]';
  $handler->display->display_options['fields']['title']['alter']['make_link'] = TRUE;
  $handler->display->display_options['fields']['title']['alter']['path'] = 'node/[nid]';
  $handler->display->display_options['fields']['title']['alter']['absolute'] = TRUE;
  $handler->display->display_options['fields']['title']['alter']['word_boundary'] = FALSE;
  $handler->display->display_options['fields']['title']['alter']['ellipsis'] = FALSE;
  $handler->display->display_options['fields']['title']['element_label_colon'] = FALSE;
  $handler->display->display_options['fields']['title']['link_to_node'] = FALSE;
  /* Field: Product: Add to cart form */
  $handler->display->display_options['fields']['addtocartlink']['id'] = 'addtocartlink';
  $handler->display->display_options['fields']['addtocartlink']['table'] = 'uc_products';
  $handler->display->display_options['fields']['addtocartlink']['field'] = 'addtocartlink';
  $handler->display->display_options['fields']['addtocartlink']['relationship'] = 'translation';
  $handler->display->display_options['fields']['addtocartlink']['label'] = '';
  $handler->display->display_options['fields']['addtocartlink']['element_label_colon'] = FALSE;
  $handler->display->display_options['defaults']['arguments'] = FALSE;
  /* Contextual filter: Content: Nid */
  $handler->display->display_options['arguments']['nid_1']['id'] = 'nid_1';
  $handler->display->display_options['arguments']['nid_1']['table'] = 'node';
  $handler->display->display_options['arguments']['nid_1']['field'] = 'nid';
  $handler->display->display_options['arguments']['nid_1']['default_action'] = 'default';
  $handler->display->display_options['arguments']['nid_1']['default_argument_type'] = 'node';
  $handler->display->display_options['arguments']['nid_1']['summary']['number_of_records'] = '0';
  $handler->display->display_options['arguments']['nid_1']['summary']['format'] = 'default_summary';
  $handler->display->display_options['arguments']['nid_1']['summary_options']['items_per_page'] = '25';
  /* Contextual filter: Content: Nid */
  $handler->display->display_options['arguments']['nid']['id'] = 'nid';
  $handler->display->display_options['arguments']['nid']['table'] = 'node';
  $handler->display->display_options['arguments']['nid']['field'] = 'nid';
  $handler->display->display_options['arguments']['nid']['relationship'] = 'translation';
  $handler->display->display_options['arguments']['nid']['default_action'] = 'default';
  $handler->display->display_options['arguments']['nid']['default_argument_type'] = 'node';
  $handler->display->display_options['arguments']['nid']['summary']['number_of_records'] = '0';
  $handler->display->display_options['arguments']['nid']['summary']['format'] = 'default_summary';
  $handler->display->display_options['arguments']['nid']['summary_options']['items_per_page'] = '25';
  $handler->display->display_options['arguments']['nid']['not'] = TRUE;
  $handler->display->display_options['defaults']['filter_groups'] = FALSE;
  $handler->display->display_options['defaults']['filters'] = FALSE;
  /* Filter criterion: Content: Published */
  $handler->display->display_options['filters']['status']['id'] = 'status';
  $handler->display->display_options['filters']['status']['table'] = 'node';
  $handler->display->display_options['filters']['status']['field'] = 'status';
  $handler->display->display_options['filters']['status']['value'] = 1;
  $handler->display->display_options['filters']['status']['group'] = 1;
  $handler->display->display_options['filters']['status']['expose']['operator'] = FALSE;
  /* Filter criterion: Content: Type */
  $handler->display->display_options['filters']['type']['id'] = 'type';
  $handler->display->display_options['filters']['type']['table'] = 'node';
  $handler->display->display_options['filters']['type']['field'] = 'type';
  $handler->display->display_options['filters']['type']['value'] = array(
    'ofed_uc_publication' => 'ofed_uc_publication',
  );

  /* Display: Related publications */
  $handler = $view->new_display('attachment', 'Related publications', 'attachment_1');
  $handler->display->display_options['display_description'] = 'when on a main node, show all the related nodes of that node';
  $handler->display->display_options['pager']['type'] = 'none';
  $handler->display->display_options['pager']['options']['offset'] = '0';
  $handler->display->display_options['defaults']['relationships'] = FALSE;
  /* Relationship: Entity Reference: Referenced Entity */
  $handler->display->display_options['relationships']['field_ofed_uc_publication_relpub_target_id']['id'] = 'field_ofed_uc_publication_relpub_target_id';
  $handler->display->display_options['relationships']['field_ofed_uc_publication_relpub_target_id']['table'] = 'field_data_field_ofed_uc_publication_relpub';
  $handler->display->display_options['relationships']['field_ofed_uc_publication_relpub_target_id']['field'] = 'field_ofed_uc_publication_relpub_target_id';
  $handler->display->display_options['relationships']['field_ofed_uc_publication_relpub_target_id']['required'] = TRUE;
  $handler->display->display_options['defaults']['fields'] = FALSE;
  /* Field: Content: Nid */
  $handler->display->display_options['fields']['nid']['id'] = 'nid';
  $handler->display->display_options['fields']['nid']['table'] = 'node';
  $handler->display->display_options['fields']['nid']['field'] = 'nid';
  $handler->display->display_options['fields']['nid']['relationship'] = 'field_ofed_uc_publication_relpub_target_id';
  $handler->display->display_options['fields']['nid']['label'] = '';
  $handler->display->display_options['fields']['nid']['exclude'] = TRUE;
  $handler->display->display_options['fields']['nid']['element_label_colon'] = FALSE;
  /* Field: Content: Language */
  $handler->display->display_options['fields']['language']['id'] = 'language';
  $handler->display->display_options['fields']['language']['table'] = 'node';
  $handler->display->display_options['fields']['language']['field'] = 'language';
  $handler->display->display_options['fields']['language']['relationship'] = 'field_ofed_uc_publication_relpub_target_id';
  $handler->display->display_options['fields']['language']['label'] = '';
  $handler->display->display_options['fields']['language']['exclude'] = TRUE;
  $handler->display->display_options['fields']['language']['alter']['alter_text'] = TRUE;
  $handler->display->display_options['fields']['language']['alter']['text'] = '([language])';
  $handler->display->display_options['fields']['language']['element_label_colon'] = FALSE;
  /* Field: Content: Title */
  $handler->display->display_options['fields']['title']['id'] = 'title';
  $handler->display->display_options['fields']['title']['table'] = 'node';
  $handler->display->display_options['fields']['title']['field'] = 'title';
  $handler->display->display_options['fields']['title']['relationship'] = 'field_ofed_uc_publication_relpub_target_id';
  $handler->display->display_options['fields']['title']['label'] = '';
  $handler->display->display_options['fields']['title']['alter']['alter_text'] = TRUE;
  $handler->display->display_options['fields']['title']['alter']['text'] = '[title] [language]';
  $handler->display->display_options['fields']['title']['alter']['make_link'] = TRUE;
  $handler->display->display_options['fields']['title']['alter']['path'] = 'node/[nid]';
  $handler->display->display_options['fields']['title']['alter']['absolute'] = TRUE;
  $handler->display->display_options['fields']['title']['alter']['word_boundary'] = FALSE;
  $handler->display->display_options['fields']['title']['alter']['ellipsis'] = FALSE;
  $handler->display->display_options['fields']['title']['element_label_colon'] = FALSE;
  $handler->display->display_options['fields']['title']['link_to_node'] = FALSE;
  /* Field: Product: Add to cart form */
  $handler->display->display_options['fields']['addtocartlink']['id'] = 'addtocartlink';
  $handler->display->display_options['fields']['addtocartlink']['table'] = 'uc_products';
  $handler->display->display_options['fields']['addtocartlink']['field'] = 'addtocartlink';
  $handler->display->display_options['fields']['addtocartlink']['relationship'] = 'field_ofed_uc_publication_relpub_target_id';
  $handler->display->display_options['fields']['addtocartlink']['label'] = '';
  $handler->display->display_options['fields']['addtocartlink']['element_label_colon'] = FALSE;
  $handler->display->display_options['defaults']['arguments'] = FALSE;
  /* Contextual filter: Content: Nid */
  $handler->display->display_options['arguments']['nid_1']['id'] = 'nid_1';
  $handler->display->display_options['arguments']['nid_1']['table'] = 'node';
  $handler->display->display_options['arguments']['nid_1']['field'] = 'nid';
  $handler->display->display_options['arguments']['nid_1']['default_action'] = 'default';
  $handler->display->display_options['arguments']['nid_1']['default_argument_type'] = 'node';
  $handler->display->display_options['arguments']['nid_1']['summary']['number_of_records'] = '0';
  $handler->display->display_options['arguments']['nid_1']['summary']['format'] = 'default_summary';
  $handler->display->display_options['arguments']['nid_1']['summary_options']['items_per_page'] = '25';
  $handler->display->display_options['displays'] = array(
    'publication_languages' => 'publication_languages',
    'default' => 0,
  );
  $handler->display->display_options['attachment_position'] = 'after';

  /* Display: Translated Publications - On a Related Node */
  $handler = $view->new_display('attachment', 'Translated Publications - On a Related Node', 'attachment_2');
  $handler->display->display_options['display_description'] = 'when seeing a related node, this will show the translated node of the "main" node of the current language';
  $handler->display->display_options['pager']['type'] = 'none';
  $handler->display->display_options['pager']['options']['offset'] = '0';
  $handler->display->display_options['defaults']['relationships'] = FALSE;
  /* Relationship: Content translation: Source translation */
  $handler->display->display_options['relationships']['tnid']['id'] = 'tnid';
  $handler->display->display_options['relationships']['tnid']['table'] = 'node';
  $handler->display->display_options['relationships']['tnid']['field'] = 'tnid';
  $handler->display->display_options['relationships']['tnid']['required'] = TRUE;
  /* Relationship: Content translation: Translations */
  $handler->display->display_options['relationships']['translation']['id'] = 'translation';
  $handler->display->display_options['relationships']['translation']['table'] = 'node';
  $handler->display->display_options['relationships']['translation']['field'] = 'translation';
  $handler->display->display_options['relationships']['translation']['relationship'] = 'tnid';
  $handler->display->display_options['relationships']['translation']['required'] = TRUE;
  $handler->display->display_options['relationships']['translation']['language'] = 'all';
  $handler->display->display_options['defaults']['fields'] = FALSE;
  /* Field: Content: Nid */
  $handler->display->display_options['fields']['nid']['id'] = 'nid';
  $handler->display->display_options['fields']['nid']['table'] = 'node';
  $handler->display->display_options['fields']['nid']['field'] = 'nid';
  $handler->display->display_options['fields']['nid']['relationship'] = 'translation';
  $handler->display->display_options['fields']['nid']['label'] = '';
  $handler->display->display_options['fields']['nid']['exclude'] = TRUE;
  $handler->display->display_options['fields']['nid']['element_label_colon'] = FALSE;
  /* Field: Content: Language */
  $handler->display->display_options['fields']['language']['id'] = 'language';
  $handler->display->display_options['fields']['language']['table'] = 'node';
  $handler->display->display_options['fields']['language']['field'] = 'language';
  $handler->display->display_options['fields']['language']['relationship'] = 'translation';
  $handler->display->display_options['fields']['language']['label'] = '';
  $handler->display->display_options['fields']['language']['exclude'] = TRUE;
  $handler->display->display_options['fields']['language']['alter']['alter_text'] = TRUE;
  $handler->display->display_options['fields']['language']['alter']['text'] = '([language])';
  $handler->display->display_options['fields']['language']['element_label_colon'] = FALSE;
  /* Field: Content: Title */
  $handler->display->display_options['fields']['title']['id'] = 'title';
  $handler->display->display_options['fields']['title']['table'] = 'node';
  $handler->display->display_options['fields']['title']['field'] = 'title';
  $handler->display->display_options['fields']['title']['relationship'] = 'translation';
  $handler->display->display_options['fields']['title']['label'] = '';
  $handler->display->display_options['fields']['title']['alter']['alter_text'] = TRUE;
  $handler->display->display_options['fields']['title']['alter']['text'] = '[title] [language]';
  $handler->display->display_options['fields']['title']['alter']['make_link'] = TRUE;
  $handler->display->display_options['fields']['title']['alter']['path'] = 'node/[nid]';
  $handler->display->display_options['fields']['title']['alter']['absolute'] = TRUE;
  $handler->display->display_options['fields']['title']['alter']['word_boundary'] = FALSE;
  $handler->display->display_options['fields']['title']['alter']['ellipsis'] = FALSE;
  $handler->display->display_options['fields']['title']['element_label_colon'] = FALSE;
  $handler->display->display_options['fields']['title']['link_to_node'] = FALSE;
  /* Field: Product: Add to cart form */
  $handler->display->display_options['fields']['addtocartlink']['id'] = 'addtocartlink';
  $handler->display->display_options['fields']['addtocartlink']['table'] = 'uc_products';
  $handler->display->display_options['fields']['addtocartlink']['field'] = 'addtocartlink';
  $handler->display->display_options['fields']['addtocartlink']['relationship'] = 'translation';
  $handler->display->display_options['fields']['addtocartlink']['label'] = '';
  $handler->display->display_options['fields']['addtocartlink']['element_label_colon'] = FALSE;
  $handler->display->display_options['defaults']['arguments'] = FALSE;
  /* Contextual filter: Content: Related publications (field_ofed_uc_publication_relpub) */
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['id'] = 'field_ofed_uc_publication_relpub_target_id';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['table'] = 'field_data_field_ofed_uc_publication_relpub';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['field'] = 'field_ofed_uc_publication_relpub_target_id';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['default_action'] = 'default';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['default_argument_type'] = 'raw';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['default_argument_options']['index'] = '1';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['summary']['number_of_records'] = '0';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['summary']['format'] = 'default_summary';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['summary_options']['items_per_page'] = '25';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['specify_validation'] = TRUE;
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['validate']['type'] = 'node';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['validate_options']['types'] = array(
    'ofed_uc_publication' => 'ofed_uc_publication',
  );
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['validate']['fail'] = 'empty';
  $handler->display->display_options['defaults']['filter_groups'] = FALSE;
  $handler->display->display_options['defaults']['filters'] = FALSE;
  /* Filter criterion: Content: Published */
  $handler->display->display_options['filters']['status']['id'] = 'status';
  $handler->display->display_options['filters']['status']['table'] = 'node';
  $handler->display->display_options['filters']['status']['field'] = 'status';
  $handler->display->display_options['filters']['status']['value'] = 1;
  $handler->display->display_options['filters']['status']['group'] = 1;
  $handler->display->display_options['filters']['status']['expose']['operator'] = FALSE;
  /* Filter criterion: Content: Type */
  $handler->display->display_options['filters']['type']['id'] = 'type';
  $handler->display->display_options['filters']['type']['table'] = 'node';
  $handler->display->display_options['filters']['type']['field'] = 'type';
  $handler->display->display_options['filters']['type']['value'] = array(
    'ofed_uc_publication' => 'ofed_uc_publication',
  );
  /* Filter criterion: Content: Language */
  $handler->display->display_options['filters']['language']['id'] = 'language';
  $handler->display->display_options['filters']['language']['table'] = 'node';
  $handler->display->display_options['filters']['language']['field'] = 'language';
  $handler->display->display_options['filters']['language']['operator'] = 'not in';
  $handler->display->display_options['filters']['language']['value'] = array(
    '***CURRENT_LANGUAGE***' => '***CURRENT_LANGUAGE***',
  );
  /* Filter criterion: Content: Language */
  $handler->display->display_options['filters']['language_1']['id'] = 'language_1';
  $handler->display->display_options['filters']['language_1']['table'] = 'node';
  $handler->display->display_options['filters']['language_1']['field'] = 'language';
  $handler->display->display_options['filters']['language_1']['relationship'] = 'translation';
  $handler->display->display_options['filters']['language_1']['operator'] = 'not in';
  $handler->display->display_options['filters']['language_1']['value'] = array(
    '***CURRENT_LANGUAGE***' => '***CURRENT_LANGUAGE***',
  );
  $handler->display->display_options['displays'] = array(
    'publication_languages' => 'publication_languages',
    'default' => 0,
  );
  $handler->display->display_options['attachment_position'] = 'after';

  /* Display: Related Publications - On a Related Node */
  $handler = $view->new_display('attachment', 'Related Publications - On a Related Node', 'attachment_3');
  $handler->display->display_options['display_description'] = 'when seeing a related node, this will show the related nodes of the "main" node of the current language';
  $handler->display->display_options['pager']['type'] = 'none';
  $handler->display->display_options['pager']['options']['offset'] = '0';
  $handler->display->display_options['defaults']['relationships'] = FALSE;
  /* Relationship: Entity Reference: Referencing entity */
  $handler->display->display_options['relationships']['reverse_field_ofed_uc_publication_relpub_node']['id'] = 'reverse_field_ofed_uc_publication_relpub_node';
  $handler->display->display_options['relationships']['reverse_field_ofed_uc_publication_relpub_node']['table'] = 'node';
  $handler->display->display_options['relationships']['reverse_field_ofed_uc_publication_relpub_node']['field'] = 'reverse_field_ofed_uc_publication_relpub_node';
  $handler->display->display_options['relationships']['reverse_field_ofed_uc_publication_relpub_node']['required'] = TRUE;
  /* Relationship: Entity Reference: Referenced Entity */
  $handler->display->display_options['relationships']['field_ofed_uc_publication_relpub_target_id']['id'] = 'field_ofed_uc_publication_relpub_target_id';
  $handler->display->display_options['relationships']['field_ofed_uc_publication_relpub_target_id']['table'] = 'field_data_field_ofed_uc_publication_relpub';
  $handler->display->display_options['relationships']['field_ofed_uc_publication_relpub_target_id']['field'] = 'field_ofed_uc_publication_relpub_target_id';
  $handler->display->display_options['relationships']['field_ofed_uc_publication_relpub_target_id']['relationship'] = 'reverse_field_ofed_uc_publication_relpub_node';
  $handler->display->display_options['relationships']['field_ofed_uc_publication_relpub_target_id']['required'] = TRUE;
  $handler->display->display_options['defaults']['arguments'] = FALSE;
  /* Contextual filter: Content: Related publications (field_ofed_uc_publication_relpub) */
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['id'] = 'field_ofed_uc_publication_relpub_target_id';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['table'] = 'field_data_field_ofed_uc_publication_relpub';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['field'] = 'field_ofed_uc_publication_relpub_target_id';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['relationship'] = 'reverse_field_ofed_uc_publication_relpub_node';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['default_action'] = 'default';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['default_argument_type'] = 'raw';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['default_argument_options']['index'] = '1';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['summary']['number_of_records'] = '0';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['summary']['format'] = 'default_summary';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['summary_options']['items_per_page'] = '25';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['specify_validation'] = TRUE;
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['validate']['type'] = 'node';
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['validate_options']['types'] = array(
    'ofed_uc_publication' => 'ofed_uc_publication',
  );
  $handler->display->display_options['arguments']['field_ofed_uc_publication_relpub_target_id']['validate']['fail'] = 'empty';
  /* Contextual filter: Content: Nid */
  $handler->display->display_options['arguments']['nid']['id'] = 'nid';
  $handler->display->display_options['arguments']['nid']['table'] = 'node';
  $handler->display->display_options['arguments']['nid']['field'] = 'nid';
  $handler->display->display_options['arguments']['nid']['default_action'] = 'default';
  $handler->display->display_options['arguments']['nid']['default_argument_type'] = 'node';
  $handler->display->display_options['arguments']['nid']['summary']['number_of_records'] = '0';
  $handler->display->display_options['arguments']['nid']['summary']['format'] = 'default_summary';
  $handler->display->display_options['arguments']['nid']['summary_options']['items_per_page'] = '25';
  $handler->display->display_options['arguments']['nid']['specify_validation'] = TRUE;
  $handler->display->display_options['arguments']['nid']['validate']['type'] = 'node';
  $handler->display->display_options['arguments']['nid']['validate_options']['types'] = array(
    'ofed_uc_publication' => 'ofed_uc_publication',
  );
  $handler->display->display_options['arguments']['nid']['not'] = TRUE;
  $handler->display->display_options['defaults']['filter_groups'] = FALSE;
  $handler->display->display_options['defaults']['filters'] = FALSE;
  /* Filter criterion: Content: Published */
  $handler->display->display_options['filters']['status']['id'] = 'status';
  $handler->display->display_options['filters']['status']['table'] = 'node';
  $handler->display->display_options['filters']['status']['field'] = 'status';
  $handler->display->display_options['filters']['status']['value'] = 1;
  $handler->display->display_options['filters']['status']['group'] = 1;
  $handler->display->display_options['filters']['status']['expose']['operator'] = FALSE;
  /* Filter criterion: Content: Type */
  $handler->display->display_options['filters']['type']['id'] = 'type';
  $handler->display->display_options['filters']['type']['table'] = 'node';
  $handler->display->display_options['filters']['type']['field'] = 'type';
  $handler->display->display_options['filters']['type']['value'] = array(
    'ofed_uc_publication' => 'ofed_uc_publication',
  );
  /* Filter criterion: Content: Language */
  $handler->display->display_options['filters']['language']['id'] = 'language';
  $handler->display->display_options['filters']['language']['table'] = 'node';
  $handler->display->display_options['filters']['language']['field'] = 'language';
  $handler->display->display_options['filters']['language']['relationship'] = 'reverse_field_ofed_uc_publication_relpub_node';
  $handler->display->display_options['filters']['language']['value'] = array(
    '***CURRENT_LANGUAGE***' => '***CURRENT_LANGUAGE***',
  );
  $handler->display->display_options['displays'] = array(
    'publication_languages' => 'publication_languages',
    'default' => 0,
  );
  $handler->display->display_options['attachment_position'] = 'after';
  $translatables['publication_translations'] = array(
    t('Master'),
    t('Order'),
    t('more'),
    t('Apply'),
    t('Reset'),
    t('Sort by'),
    t('Asc'),
    t('Desc'),
    t('Source translation'),
    t('Translations'),
    t('([language])'),
    t('[title] [language]'),
    t('All'),
    t('Current Publication'),
    t('The link/form to the current node'),
    t('Current Language Main Node'),
    t('show the main node of the current language, the one that have all the related items'),
    t('Translated Publications'),
    t('when on a main node, of one of the site languages, show all the translations for that node'),
    t('Related publications'),
    t('when on a main node, show all the related nodes of that node'),
    t('Content entity referenced from field_ofed_uc_publication_relpub'),
    t('Translated Publications - On a Related Node'),
    t('when seeing a related node, this will show the translated node of the "main" node of the current language'),
    t('Related Publications - On a Related Node'),
    t('when seeing a related node, this will show the related nodes of the "main" node of the current language'),
    t('Content referencing Content from field_ofed_uc_publication_relpub'),
  );
  $export['publication_translations'] = $view;

  return $export;
}
