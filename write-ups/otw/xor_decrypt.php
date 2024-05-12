<?php

$thedata0 = "MGw7JCQ5OC04PT8jOSpqdmkgJ25nbCorKCEkIzlscm5oKC4qLSgubjY%3D";  #ffffff
#$thedata1 = "MGw7JCQ5OC04PT8jOSpqdmkgJ25nbCorKCEkIzlscm5oKHstKnwpbjY%3D";  #f3aa2a
#$thedata2 = "MGw7JCQ5OC04PT8jOSpqdmkgJ25nbCorKCEkIzlscm5oKHt4f3wpbjY%3D";  #f3442a

$defaultdata = array( "showpassword"=>"no", "bgcolor"=>"#ffffff");

$malicious_data = array( "showpassword"=>"yes", "bgcolor"=>"#ffffff");

function xor_encrypt($in, $key) {
    #$key = "0l;$$98-8=?#9*jvi 'ngl*+(!$#9lrnh(.*-(.n67";
    $text = $in;
    $outText = '';

    // Iterate through each character
    for($i=0;$i<strlen($text);$i++) {
    $outText .= $text[$i] ^ $key[$i % strlen($key)];
    }

    return $outText;
}

function loadData($def) {
    global $_COOKIE;
    $mydata = $def;
    if(array_key_exists("data", $_COOKIE)) {
    $tempdata = json_decode(xor_encrypt(base64_decode($_COOKIE["data"])), true);
    if(is_array($tempdata) && array_key_exists("showpassword", $tempdata) && array_key_exists("bgcolor", $tempdata)) {
        if (preg_match('/^#(?:[a-f\d]{6})$/i', $tempdata['bgcolor'])) {
        $mydata['showpassword'] = $tempdata['showpassword'];
        $mydata['bgcolor'] = $tempdata['bgcolor'];
        }
    }
    }
    return $mydata;
}

function saveData($d) {
    setcookie("data", base64_encode(xor_encrypt(json_encode($d))));
}

$decoded = base64_decode($thedata0);
#$decoded = xor_encrypt(base64_decode($thedata0));
print $decoded;
print "\n";

print json_encode($defaultdata);
print "\n";

print xor_encrypt(json_encode($defaultdata), "0l;$$98-8=?#9*jvi 'ngl*+(!$#9lrnh(.*-(.n67");
print "\n";


print xor_encrypt(json_encode($defaultdata), "KNHL");
print "\n";

print "answer:\n";
print base64_encode(xor_encrypt(json_encode($malicious_data), "KNHL"));
print "\n";


# defaultdata_json = base64_decode(thedata) XOR key
# defaultdata_json XOR base64_decode(thedata) = key

# wanted =

#$data = loadData($defaultdata);

#if(array_key_exists("bgcolor",$_REQUEST)) {
#    if (preg_match('/^#(?:[a-f\d]{6})$/i', $_REQUEST['bgcolor'])) {
#        $data['bgcolor'] = $_REQUEST['bgcolor'];
#    }
#}

#saveData($data);

?>
