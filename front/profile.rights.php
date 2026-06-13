<?php

use GlpiPlugin\Tanium\Profile as TaniumProfile;

include('../../../inc/includes.php');

Session::checkRight('profile', UPDATE);

$profileId = (int) ($_POST['profiles_id'] ?? 0);
if ($profileId <= 0) {
    Session::addMessageAfterRedirect(__('Profile not found.', 'tanium'), false, ERROR);
    Html::back();
}

TaniumProfile::saveRightsForProfile($profileId, (array) ($_POST['plugin_tanium_rights'] ?? []));
Session::addMessageAfterRedirect(__('Tanium permissions updated successfully.', 'tanium'), false, INFO);
Html::redirect('/front/profile.form.php?id=' . $profileId);
