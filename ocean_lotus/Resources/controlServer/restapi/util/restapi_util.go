package restapi_util

import (
    "bytes"
    "fmt"
    "encoding/json"

    "attackevals.mitre-engenuity.org/control_server/config"	
    "attackevals.mitre-engenuity.org/control_server/logger"
    "attackevals.mitre-engenuity.org/control_server/sessions"
    "attackevals.mitre-engenuity.org/control_server/tasks"
)

// API response types and status codes
const (
    RESP_TYPE_CTRL = 0 // API control messages (for error messages, generic success messages). Will contain string data
    RESP_TYPE_VERSION = 1 // version message (for GetVersion). Will contain string data
    RESP_TYPE_CONFIG = 2 // config message (for GetConfig). Will contain json data
    RESP_TYPE_SESSIONS = 3 // C2 sessions message (for GetSessionByGuid and GetSessions). Will contain json data
    RESP_TYPE_TASK_CMD = 4 // task command message (for GetTaskCommandBySessionId and GetBootstrapTask). Will contain string data
    RESP_TYPE_TASK_OUTPUT = 5 // task output message (for GetTaskOutputBySessionId and GetTaskOutput). Will contain string data
    RESP_TYPE_TASK_INFO = 6 // task data message (for GetTask). Will contain json data
    RESP_STATUS_SUCCESS = 0
    RESP_STATUS_FAILURE = 1
)

// API response struct for string data
type ApiStringResponse struct {
    ResponseType    int     `json:"type"`
    Status          int     `json:"status"`
    Data            string  `json:"data"`
}

// API response struct for config JSON data
type ApiConfigResponse struct {
    ResponseType    int                         `json:"type"`
    Status          int                         `json:"status"`
    Data            config.RestAPIConfigStruct  `json:"data"`
}

// API response struct for sessions JSON data
type ApiSessionsResponse struct {
    ResponseType    int                 `json:"type"`
    Status          int                 `json:"status"`
    Data            []sessions.Session  `json:"data"`
}

// API response struct for task JSON data
type ApiTaskResponse struct {
    ResponseType    int         `json:"type"`
    Status          int         `json:"status"`
    Data            tasks.Task  `json:"data"`
}

func CreateBarebonesErrorJsonStr(errorMsg string) []byte {
    return []byte(fmt.Sprintf("{\n  \"type\": %d,\n  \"status\": %d,\n  \"data\": %s\n}\n", RESP_TYPE_CTRL, RESP_STATUS_FAILURE, errorMsg))
}

// Helper function to manually marshal JSON without HTML encoding (avoid HTML encoding &, <, >) and with indent len of 2
func JsonMarshalIndentNoHtmlEncode(v any) ([]byte, error) {
    buffer := &bytes.Buffer{}
    encoder := json.NewEncoder(buffer)
    encoder.SetEscapeHTML(false)
    encoder.SetIndent("", "  ")
    err := encoder.Encode(v)
    if err != nil {
        return nil, err
    }
    return buffer.Bytes(), err
}

// Creates formatted JSON response for string-based API response messages
func CreateStringResponseJSON(responseType int, statusCode int, message string) []byte {
    resp := ApiStringResponse{
        ResponseType: responseType,
        Status: statusCode,
        Data: message,
    }
    encodedResp, err := JsonMarshalIndentNoHtmlEncode(resp)
    if err != nil {
        errorMsg := fmt.Sprintf("Failed to marshal API string response as JSON: %s", err.Error())
        logger.Error(errorMsg)
        return CreateBarebonesErrorJsonStr(errorMsg)
    }
    return encodedResp
}

// Creates formatted JSON response for config API response messages
func CreateConfigResponseJSON(statusCode int, configData config.RestAPIConfigStruct) []byte {
    resp := ApiConfigResponse{
        ResponseType: RESP_TYPE_CONFIG,
        Status: statusCode,
        Data: configData,
    }
    encodedResp, err := JsonMarshalIndentNoHtmlEncode(resp)
    if err != nil {
        errorMsg := fmt.Sprintf("Failed to marshal API config response as JSON: %s", err.Error())
        logger.Error(errorMsg)
        return CreateBarebonesErrorJsonStr(errorMsg)
    }
    return encodedResp
}

// Creates formatted JSON response for sessions API response messages
func CreateSessionsResponseJSON(statusCode int, sessionData []sessions.Session) []byte {
    resp := ApiSessionsResponse{
        ResponseType: RESP_TYPE_SESSIONS,
        Status: statusCode,
        Data: sessionData,
    }
    encodedResp, err := JsonMarshalIndentNoHtmlEncode(resp)
    if err != nil {
        errorMsg := fmt.Sprintf("Failed to marshal API session response as JSON: %s", err.Error())
        logger.Error(errorMsg)
        return CreateBarebonesErrorJsonStr(errorMsg)
    }
    return encodedResp
}

// Creates formatted JSON response for task API response messages
func CreateTaskInfoResponseJSON(statusCode int, taskData tasks.Task) []byte{
    resp := ApiTaskResponse{
        ResponseType: RESP_TYPE_TASK_INFO,
        Status: statusCode,
        Data: taskData,
    }
    encodedResp, err := JsonMarshalIndentNoHtmlEncode(resp)
    if err != nil {
        errorMsg := fmt.Sprintf("Failed to marshal API task response as JSON: %s", err.Error())
        logger.Error(errorMsg)
        return CreateBarebonesErrorJsonStr(errorMsg)
    }
    return encodedResp
}
