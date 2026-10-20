<?php
function local_user_set_password(&$user, $password) { $user['bcrypt-hash'] = 'stub-hash'; }
function local_user_set($user) { _test_record('local_user_set', [$user['name']]); }
function local_group_set($group) { _test_record('local_group_set', [$group['name']]); }
