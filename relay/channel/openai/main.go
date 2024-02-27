package openai

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"one-api/common"
	"one-api/relay/constant"
	"one-api/relay/model"
	"strings"

	"github.com/gin-gonic/gin"
)

func StreamHandler(c *gin.Context, resp *http.Response, relayMode int, fixedContent string) (*model.ErrorWithStatusCode, string) {
	responseText := ""
	scanner := bufio.NewScanner(resp.Body)
	scanner.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}
		if i := strings.Index(string(data), "\n"); i >= 0 {
			return i + 1, data[0:i], nil
		}
		if atEOF {
			return len(data), data, nil
		}
		return 0, nil, nil
	})
	dataChan := make(chan string)
	stopChan := make(chan bool)

	go func() {
		var needInjectFixedMessageBeforeNextSend = false
		for scanner.Scan() {
			data := scanner.Text()
			if len(data) < 6 { // ignore blank line or wrong format
				continue
			}
			// 先根据需要注入固定内容，再处理接下来的数据
			if needInjectFixedMessageBeforeNextSend && fixedContent != "" {
				fixedContentMessage := GenerateFixedContentMessage(fixedContent)
				dataChan <- fixedContentMessage              // 发送固定内容
				needInjectFixedMessageBeforeNextSend = false // 重置标志位
			}
			if data[:6] != "data: " && data[:6] != "[DONE]" {
				continue
			}

			if data[:6] == "data: " {
				jsonData := data[6:]
				if jsonData == "[DONE]" {
					//needInjectFixedMessageBeforeNextSend = true
					continue
				}

				switch relayMode {
				case constant.RelayModeChatCompletions:
					var streamResponse ChatCompletionsStreamResponse
					err := json.Unmarshal([]byte(jsonData), &streamResponse)
					if err != nil {
						common.SysError("error unmarshalling stream response: " + err.Error())
						continue // just ignore the error
					}
					for _, choice := range streamResponse.Choices {
						responseText += choice.Delta.Content
						if choice.FinishReason != nil && *choice.FinishReason == "stop" {
							needInjectFixedMessageBeforeNextSend = true
						}
					}

				case constant.RelayModeCompletions:
					var streamResponse CompletionsStreamResponse
					err := json.Unmarshal([]byte(jsonData), &streamResponse)
					if err != nil {
						common.SysError("error unmarshalling stream response: " + err.Error())
						continue
					}
					for _, choice := range streamResponse.Choices {
						responseText += choice.Text
						if choice.FinishReason == "stop" {
							needInjectFixedMessageBeforeNextSend = true
						}
					}
				}

			}
			if !needInjectFixedMessageBeforeNextSend {
				dataChan <- data // 正常发送
			}

		}
		// 如果循环结束（比如遇到EOF），也检查是否有最后的固定内容需要注入
		if needInjectFixedMessageBeforeNextSend && fixedContent != "" {
			fixedContentMessage := GenerateFixedContentMessage(fixedContent)
			dataChan <- fixedContentMessage
		}
		doneSignal := "data: [DONE]"
		dataChan <- doneSignal // 发送结束信号
		stopChan <- true
	}()
	common.SetEventStreamHeaders(c)
	c.Stream(func(w io.Writer) bool {
		select {
		case data := <-dataChan:
			if strings.HasPrefix(data, "data: [DONE]") {
				data = data[:12]
			}
			// some implementations may add \r at the end of data
			data = strings.TrimSuffix(data, "\r")
			c.Render(-1, common.CustomEvent{Data: data})
			return true
		case <-stopChan:
			return false
		}
	})
	err := resp.Body.Close()
	if err != nil {
		return ErrorWrapper(err, "close_response_body_failed", http.StatusInternalServerError), ""
	}
	return nil, responseText
}

func Handler(c *gin.Context, resp *http.Response, promptTokens int, modelName string) (*model.ErrorWithStatusCode, *model.Usage, string) {
	var textResponse SlimTextResponse
	var responseText string
	fixedContent := c.GetString("fixed_content")
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return ErrorWrapper(err, "read_response_body_failed", http.StatusInternalServerError), nil, ""
	}
	err = resp.Body.Close()
	if err != nil {
		return ErrorWrapper(err, "close_response_body_failed", http.StatusInternalServerError), nil, ""
	}
	err = json.Unmarshal(responseBody, &textResponse)
	if err != nil {
		return ErrorWrapper(err, "unmarshal_response_body_failed", http.StatusInternalServerError), nil, ""
	}
	if textResponse.Error.Type != "" {
		return &model.ErrorWithStatusCode{
			Error:      textResponse.Error,
			StatusCode: resp.StatusCode,
		}, nil, ""
	}
	for _, choice := range textResponse.Choices {
		responseText = choice.Message.StringContent()
	}
	// 在响应文本中插入固定内容，并构建包含 fixedContent 的 responseText
	if fixedContent != "" {
		for i, choice := range textResponse.Choices {
			modifiedContent := choice.Message.StringContent() + "\n\n" + fixedContent
			// 使用json.Marshal确保字符串被正确编码为JSON
			encodedContent, err := json.Marshal(modifiedContent)
			if err != nil {
				return ErrorWrapper(err, "encode_modified_content_failed", http.StatusInternalServerError), nil, ""
			}
			textResponse.Choices[i].Message.Content = json.RawMessage(encodedContent)
		}
	}

	// Token 的计算使用原始响应文本而不包括 fixedContent
	if textResponse.Usage.TotalTokens == 0 {
		completionTokens := CountTokenText(responseText, modelName) // 假设 CountTokenText 可以正确计算
		textResponse.Usage = model.Usage{
			PromptTokens:     promptTokens,
			CompletionTokens: completionTokens,
			TotalTokens:      promptTokens + completionTokens,
		}
	}

	// 将更新后的响应发送给客户端
	modifiedResponseBody, err := json.Marshal(textResponse)
	if err != nil {
		return ErrorWrapper(err, "remarshal_response_body_failed", http.StatusInternalServerError), nil, ""
	}

	c.Writer.WriteHeader(resp.StatusCode)

	for k, v := range resp.Header {
		c.Writer.Header().Set(k, v[0])
	}
	_, err = c.Writer.Write(modifiedResponseBody)
	if err != nil {
		return ErrorWrapper(err, "write_modified_response_body_failed", http.StatusInternalServerError), nil, ""
	}

	return nil, &textResponse.Usage, responseText
}
func GenerateFixedContentMessage(fixedContent string) string {
	// 在 fixedContent 的开始处添加换行符
	modifiedFixedContent := "\n\n" + fixedContent
	content := map[string]interface{}{
		"id":      fmt.Sprintf("chatcmpl-%s", common.GetUUID()),
		"object":  "chat.completion",
		"created": common.GetTimestamp(), // 这里可能需要根据实际情况动态生成
		"choices": []map[string]interface{}{
			{
				"index":         0,
				"finish_reason": "stop",
				"delta": map[string]string{
					"content": modifiedFixedContent, // 使用修改后的 fixedContent，其中包括前置换行符
					"role":    "",
				},
			},
		},
	}

	// 将 content 转换为 JSON 字符串
	jsonBytes, err := json.Marshal(content)
	if err != nil {
		common.SysError("error marshalling fixed content message: " + err.Error())
		return ""
	}

	return "data: " + string(jsonBytes)
}
