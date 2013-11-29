<?php

/**
 * Uses a given salt instead of a random salt to allow for quick lookup.
 */
class PBKDF2_Fixed_Salt extends PBKDF2 {

  const PBKDF2_HASH_ALGORITHM = "sha512";
  const PBKDF2_ITERATIONS = 500000;
  const PBKDF2_HASH_BYTES = 24;

  const HASH_SECTIONS = 3;
  const HASH_ALGORITHM_INDEX = 0;
  const HASH_ITERATION_INDEX = 1;
  const HASH_PBKDF2_INDEX = 2;

  /**
   * @var string
   *   the fixed, known hash to use.
   */
  protected $salt;

  /**
   * @param string $salt
   *   the fixed, known hash to use.
   */
  public function __construct($salt) {
    if (!isset($salt)) {
      throw new Exception('PBKDF2 ERROR: Salt not set.');
    }
    $this->salt = $salt;
  }

  /**
   * @inheritdoc
   * Uses a fixed salt.
   */
  public function create_hash($password) {
    return PBKDF2_Fixed_Salt::PBKDF2_HASH_ALGORITHM . ":" . PBKDF2_Fixed_Salt::PBKDF2_ITERATIONS . ":" .
        base64_encode($this->hash(
            PBKDF2_Fixed_Salt::PBKDF2_HASH_ALGORITHM,
            $password,
            $this->salt,
            PBKDF2_Fixed_Salt::PBKDF2_ITERATIONS,
            PBKDF2_Fixed_Salt::PBKDF2_HASH_BYTES,
            true
       ));
  }

  /**
   * @inheritdoc
   * Uses a fixed salt.
   */
  public function validate_password($password, $good_hash) {
    $params = explode(":", $good_hash);
    if(count($params) < HASH_SECTIONS)
      return false;
    $pbkdf2 = base64_decode($params[ PBKDF2_Fixed_Salt::HASH_PBKDF2_INDEX ]);
    return slow_equals(
      $pbkdf2,
      $this->hash(
        $params[ PBKDF2_Fixed_Salt::HASH_ALGORITHM_INDEX ],
        $password,
        $this->salt,
        (int) $params[ PBKDF2_Fixed_Salt::HASH_ITERATION_INDEX ],
        strlen($pbkdf2),
        true
      )
    );
  }
}
