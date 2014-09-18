<?php
/**
 * @file
 * ofed_uc_publication.features.user_permission.inc
 */

/**
 * Implements hook_user_default_permissions().
 */
function ofed_uc_publication_user_default_permissions() {
  $permissions = array();

  // Exported permission: 'create ofed_uc_publication content'.
  $permissions['create ofed_uc_publication content'] = array(
    'name' => 'create ofed_uc_publication content',
    'roles' => array(),
    'module' => 'node',
  );

  // Exported permission: 'delete any ofed_uc_publication content'.
  $permissions['delete any ofed_uc_publication content'] = array(
    'name' => 'delete any ofed_uc_publication content',
    'roles' => array(),
    'module' => 'node',
  );

  // Exported permission: 'delete own ofed_uc_publication content'.
  $permissions['delete own ofed_uc_publication content'] = array(
    'name' => 'delete own ofed_uc_publication content',
    'roles' => array(),
    'module' => 'node',
  );

  // Exported permission: 'edit any ofed_uc_publication content'.
  $permissions['edit any ofed_uc_publication content'] = array(
    'name' => 'edit any ofed_uc_publication content',
    'roles' => array(),
    'module' => 'node',
  );

  // Exported permission: 'edit own ofed_uc_publication content'.
  $permissions['edit own ofed_uc_publication content'] = array(
    'name' => 'edit own ofed_uc_publication content',
    'roles' => array(),
    'module' => 'node',
  );

  return $permissions;
}
