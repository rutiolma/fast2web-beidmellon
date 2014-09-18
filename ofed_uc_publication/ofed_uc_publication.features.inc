<?php
/**
 * @file
 * ofed_uc_publication.features.inc
 */

/**
 * Implements hook_ctools_plugin_api().
 */
function ofed_uc_publication_ctools_plugin_api($module = NULL, $api = NULL) {
  if ($module == "strongarm" && $api == "strongarm") {
    return array("version" => "1");
  }
}

/**
 * Implements hook_views_api().
 */
function ofed_uc_publication_views_api($module = NULL, $api = NULL) {
  return array("api" => "3.0");
}

/**
 * Implements hook_uc_product_default_classes().
 */
function ofed_uc_publication_uc_product_default_classes() {
  $items = array(
    'ofed_uc_publication' => array(
      'name' => t('Publication'),
      'base' => 'uc_product',
      'description' => '',
      'has_title' => '1',
      'title_label' => t('Title'),
      'help' => '',
    ),
  );
  drupal_alter('node_info', $items);
  return $items;
}
