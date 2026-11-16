<?php
require_once __DIR__ . '/config.php';
function telegram($method, $datas = [],$botToken = null)
{
    global $ApiToken;
    if($botToken != null){
        $ApiToken = $botToken;
    }
    require_once dirname(__DIR__, 2) . '/lib/WebhookAuth.php';
    if (strtolower((string) $method) === 'setwebhook') {
        $datas['secret_token'] = FaoximaWebhookAuth::secret((string) $ApiToken, false);
    }
    $url = "https://api.telegram.org/bot" . $ApiToken . "/" . $method;
    $ch = curl_init();
    $timeout = 8;
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POSTFIELDS => $datas,
        CURLOPT_CONNECTTIMEOUT => 3,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_NOSIGNAL => true,
        CURLOPT_TCP_KEEPALIVE => 1,
    ]);
    $res = curl_exec($ch);
    $curlError = curl_error($ch);
    $curlErrno = curl_errno($ch);
    $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($res === false || $curlErrno !== 0) {
        error_log(sprintf('[vpnbot] Telegram API %s failed (curl %d): %s', (string) $method, $curlErrno, $curlError));
        return null;
    }

    $decoded = json_decode((string) $res, true);
    if (!is_array($decoded)) {
        error_log(sprintf('[vpnbot] Telegram API %s returned invalid JSON (HTTP %d)', (string) $method, $httpCode));
        return null;
    }
    return $decoded;
}
function sendmessage($chat_id,$text,$keyboard,$parse_mode){
    return telegram('sendmessage',[
        'chat_id' => $chat_id,
        'text' => $text,
        'reply_markup' => $keyboard,
        'parse_mode' => $parse_mode,

        ]);
}
function prepareTelegramInputFile($input)
{
    if ($input instanceof CURLFile) {
        return $input;
    }

    if (is_string($input)) {
        if (preg_match('/^https?:\/\//i', $input)) {
            return $input;
        }

        $realPath = realpath($input);
        if ($realPath !== false && is_file($realPath) && is_readable($realPath)) {
            return new CURLFile($realPath);
        }

        error_log(sprintf('Telegram document path is not readable: %s', $input));
        return null;
    }

    error_log('Unsupported Telegram input file type: ' . gettype($input));
    return null;
}

function sendDocument($chat_id, $documentPath, $caption) {
        $document = prepareTelegramInputFile($documentPath);
        if ($document === null) {
            return [
                'ok' => false,
                'description' => 'Document could not be prepared for Telegram upload.'
            ];
        }

        return telegram('sendDocument',[
        'chat_id' => $chat_id,
        'document' => $document,
        'caption' => $caption,
        ]);
}

function forwardMessage($chat_id,$message_id,$chat_id_user){
    telegram('forwardMessage',[
        'from_chat_id'=> $chat_id,
        'message_id'=> $message_id,
        'chat_id'=> $chat_id_user,
    ]);
}
function sendphoto($chat_id,$photoid,$caption){
    telegram('sendphoto',[
        'chat_id' => $chat_id,
        'photo'=> $photoid,
        'caption'=> $caption,
    ]);
}
function sendvideo($chat_id,$videoid,$caption){
    telegram('sendvideo',[
        'chat_id' => $chat_id,
        'video'=> $videoid,
        'caption'=> $caption,
    ]);
}
function senddocumentsid($chat_id,$documentid,$caption){
    telegram('sendDocument',[
        'chat_id' => $chat_id,
        'document'=> $documentid,
        'caption'=> $caption,
    ]);
}
function Editmessagetext($chat_id, $message_id, $text, $keyboard,$parse_mode = 'HTML'){
    return telegram('editmessagetext', [
        'chat_id' => $chat_id,
        'message_id' => $message_id,
        'text' => $text,
        'reply_markup' => $keyboard,
        'parse_mode' => $parse_mode,

    ]);
}
 function deletemessage($chat_id, $message_id){
  telegram('deletemessage', [
'chat_id' => $chat_id,
'message_id' => $message_id,
]);
 }
function getFileddire($photoid){
  return telegram('getFile', [
'file_id' => $photoid,
]);
 }
function pinmessage($from_id,$message_id){
  return telegram('pinChatMessage', [
'chat_id' => $from_id,
'message_id' => $message_id,
]);
 }
 function unpinmessage($from_id){
  return telegram('unpinAllChatMessages', [
'chat_id' => $from_id,
]);
 }
  function answerInlineQuery($inline_query_id,$results){
  return telegram('answerInlineQuery', [
      "inline_query_id" => $inline_query_id,
        "results" => json_encode($results)
]);
 }
 function convertPersianNumbersToEnglish($string) {
    $persian_numbers = ['۰', '۱', '۲', '۳', '۴', '۵', '۶', '۷', '۸', '۹'];
    $english_numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'];

    return str_replace($persian_numbers, $english_numbers, $string);
}

require_once dirname(__DIR__, 2) . '/lib/WebhookAuth.php';
FaoximaWebhookAuth::enforce((string) ($ApiToken ?? ''), false);
$update = json_decode(file_get_contents("php://input"), true);
$from_id = $update['message']['from']['id'] ?? $update['callback_query']['from']['id'] ?? $update["inline_query"]['from']['id'] ?? 0;


if (!is_numeric($from_id) || (string)(int)$from_id !== (string)$from_id) {
    error_log('[vpnbot] Rejected non-numeric from_id from webhook payload');
    http_response_code(200);
    exit;
}
$from_id = (int) $from_id;
$Chat_type = $update["message"]["chat"]["type"] ?? $update['callback_query']['message']['chat']['type'] ?? '';
$text = $update["message"]["text"]  ?? '';
$text =convertPersianNumbersToEnglish($text);
$text_inline = $update["callback_query"]["message"]['text'] ?? '';
$message_id = $update["message"]["message_id"] ?? $update["callback_query"]["message"]["message_id"] ?? 0;
$photo = $update["message"]["photo"] ?? 0;
$document = $update["message"]["document"] ?? 0;
$fileid = $update["message"]["document"]["file_id"] ?? 0;
$photoid = $photo ? end($photo)["file_id"] : '';
$caption = $update["message"]["caption"] ?? '';
$video = $update["message"]["video"] ?? 0;
$videoid = $video ? $video["file_id"] : 0;
$forward_from_id = $update["message"]["reply_to_message"]["forward_from"]["id"] ?? 0;
$datain = $update["callback_query"]["data"] ?? '';
$first_name = $update['message']['from']['first_name']  ?? $update["callback_query"]["from"]["first_name"] ?? $update["inline_query"]['from']['first_name'] ?? '';
$username = $update['message']['from']['username'] ?? $update['callback_query']['from']['username'] ?? $update["callback_query"]["from"]["username"] ?? 'NOT_USERNAME';
$user_phone =$update["message"]["contact"]["phone_number"] ?? 0;
$contact_id = $update["message"]["contact"]["user_id"] ?? 0;
$callback_query_id = $update["callback_query"]["id"] ?? 0;
$inline_query_id = $update["inline_query"]["id"] ?? 0;
$query = $update["inline_query"]["query"] ?? 0;
