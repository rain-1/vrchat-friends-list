package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
//	"unicode/utf8"
	"time"
)

type TwoFactorAuthRequest struct {
	Code string `json:"code"`
}

type AuthResponse struct {
	RequiresTwoFactorAuth []string `json:"requiresTwoFactorAuth"`
}

type VRChatUser struct {
	AcceptedTOSVersion            int      `json:"acceptedTOSVersion"`
	AcceptedPrivacyVersion        int      `json:"acceptedPrivacyVersion"`
	AccountDeletionDate           string   `json:"accountDeletionDate"`
	ActiveFriends                 []string `json:"activeFriends"`
	AllowAvatarCopying            bool     `json:"allowAvatarCopying"`
	Bio                           string   `json:"bio"`
	BioLinks                      []string `json:"bioLinks"`
	CurrentAvatar                 string   `json:"currentAvatar"`
	CurrentAvatarAssetUrl         string   `json:"currentAvatarAssetUrl"`
	CurrentAvatarImageUrl         string   `json:"currentAvatarImageUrl"`
	CurrentAvatarThumbnailImageUrl string   `json:"currentAvatarThumbnailImageUrl"`
	ID                            string   `json:"id"`
}

type Friend struct {
	Bio                            string   `json:"bio"`
	BioLinks                       []string `json:"bioLinks"`
	CurrentAvatarImageUrl          string   `json:"currentAvatarImageUrl"`
	CurrentAvatarThumbnailImageUrl string   `json:"currentAvatarThumbnailImageUrl"`
	DisplayName                    string   `json:"displayName"`
	ID                             string   `json:"id"`
	Status                         string   `json:"status"`
	StatusDescription              string   `json:"statusDescription"`
	UserIcon                       string   `json:"userIcon"`
	ProfilePicOverride             string   `json:"profilePicOverride"`
	ProfilePicOverrideThumbnail    string   `json:"profilePicOverrideThumbnail"`
	Location                       string   `json:"location"`
}

const useragent = "rain-1 vrchat-friend-list 1"

func main() {
	http.HandleFunc("/", handleLogin)
	http.HandleFunc("/auth", handleAuth)
	http.HandleFunc("/2fa", handle2FA)
	http.HandleFunc("/verify2fa", handleVerify2FA)
	http.HandleFunc("/friends", handleFriends)
	http.HandleFunc("/groups", handleGroups)
	fmt.Println("Server is running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	// TODO: If auth cookie, try to just log in straight away instead of presenting a login page

	html := `
	<!DOCTYPE html>
	<html>
	<head>
		<title>VRChat Login</title>
	</head>
	<body>
		<h1>VRChat Login</h1>
		<form action="/auth" method="post">
			<label for="username">Username:</label><br>
			<input type="text" id="username" name="username"><br>
			<label for="password">Password:</label><br>
			<input type="password" id="password" name="password"><br><br>
			<input type="submit" value="Submit">
		</form>
	</body>
	</html>
	`
	w.Write([]byte(html))
}

func handleAuth(w http.ResponseWriter, r *http.Request) {
	// if r.Method != "GET" {
	// 	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	// 	return
	// }

	username := r.FormValue("username")
	password := r.FormValue("password")

	auth := base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(username) + ":" + url.QueryEscape(password)))

	client := &http.Client{}
	req, err := http.NewRequest("GET", "https://vrchat.com/api/1/auth/user", nil)
	if err != nil {
		http.Error(w, "Error creating request", http.StatusInternalServerError)
		return
	}

	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("User-Agent", useragent)

	// Forward cookies from client to API
	for _, cookie := range r.Cookies() {
		req.AddCookie(cookie)
	}

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Error making request", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Error reading response", http.StatusInternalServerError)
		return
	}

	// Store cookies from API response to client's browser
	for _, cookie := range resp.Cookies() {
		http.SetCookie(w, cookie)
	}

	// Print result and return code to terminal
	fmt.Printf("Status Code: %d\n", resp.StatusCode)
	fmt.Printf("Response Body: %s\n", string(body))

	// // Check if 2FA is required
	// if resp.StatusCode == 200 {
	// 	// Redirect to 2FA page
	// 	http.Redirect(w, r, "/2fa", http.StatusSeeOther)
	// 	return
	// }

	var authResp AuthResponse
	err = json.Unmarshal(body, &authResp)
	if err == nil && len(authResp.RequiresTwoFactorAuth) > 0 && authResp.RequiresTwoFactorAuth[0] == "emailOtp" {
		// Redirect to 2FA page
		http.Redirect(w, r, "/2fa", http.StatusSeeOther)
		return
	}

	// If not 2FA, process the JSON response
	var user VRChatUser
	err = json.Unmarshal(body, &user)
	if err != nil {
		http.Error(w, "Error parsing JSON response", http.StatusInternalServerError)
		return
	}

	// Store the user id into a cookie for later use
	http.SetCookie(w, &http.Cookie{
		Name:    "user_id",
		Value:   user.ID,
		Expires: time.Now().Add(30 * 24 * time.Hour),
		Path:    "/",
	})

	// Generate HTML representation of the user data and friends list
	htmlContent := generateUserHTML(user)

	// Return web page with the formatted user data and friends list
	html := fmt.Sprintf(`
	<!DOCTYPE html>
	<html>
	<head>
		<title>VRChat User Info</title>
		<style>
			body { font-family: Arial, sans-serif; line-height: 1.6; padding: 20px; }
			h1 { color: #333; }
			h2 { color: #666; }
			.user-info { background-color: #f4f4f4; padding: 15px; border-radius: 5px; }
			.friends-list { margin-top: 20px; }
			.friend-id { background-color: #e9e9e9; padding: 5px; margin: 5px 0; border-radius: 3px; }
		</style>
	</head>
	<body>
		<h1>VRChat User Info</h1>
		<div class="user-info">
			%s
		</div>
	</body>
	</html>
	`, htmlContent)
	

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func generateUserHTML(user VRChatUser) string {
	var buf bytes.Buffer

	buf.WriteString(fmt.Sprintf("<h2>User Information</h2>"))
	buf.WriteString(fmt.Sprintf("<p><strong>Accepted TOS Version:</strong> %d</p>", user.AcceptedTOSVersion))
	buf.WriteString(fmt.Sprintf("<p><strong>Accepted Privacy Version:</strong> %d</p>", user.AcceptedPrivacyVersion))
	buf.WriteString(fmt.Sprintf("<p><strong>Account Deletion Date:</strong> %s</p>", template.HTMLEscapeString(user.AccountDeletionDate)))
	buf.WriteString(fmt.Sprintf("<p><strong>Allow Avatar Copying:</strong> %t</p>", user.AllowAvatarCopying))
	buf.WriteString(fmt.Sprintf("<p><strong>Bio:</strong> %s</p>", template.HTMLEscapeString(user.Bio)))
	buf.WriteString(fmt.Sprintf("<p><strong>Bio Links:</strong> %s</p>", template.HTMLEscapeString(strings.Join(user.BioLinks, ", "))))
	buf.WriteString(fmt.Sprintf("<p><strong>Current Avatar:</strong> %s</p>", template.HTMLEscapeString(user.CurrentAvatar)))
	buf.WriteString(fmt.Sprintf("<p><strong>Current Avatar Asset URL:</strong> %s</p>", template.HTMLEscapeString(user.CurrentAvatarAssetUrl)))
	buf.WriteString(fmt.Sprintf("<p><strong>Current Avatar Image URL:</strong> %s</p>", template.HTMLEscapeString(user.CurrentAvatarImageUrl)))
	//buf.WriteString(fmt.Sprintf("<img src=%s></img>", user.CurrentAvatarImageUrl))
	buf.WriteString(fmt.Sprintf("<p><strong>Current Avatar Thumbnail Image URL:</strong> %s</p>", template.HTMLEscapeString(user.CurrentAvatarThumbnailImageUrl)))
	buf.WriteString(fmt.Sprintf("<img src=%s></img>", user.CurrentAvatarThumbnailImageUrl))

	buf.WriteString("<h2>Active Friends</h2>")
	buf.WriteString("<div class='friends-list'>")
	for _, friendID := range user.ActiveFriends {
		buf.WriteString(fmt.Sprintf("<div class='friend-id'>%s</div>", template.HTMLEscapeString(friendID)))
	}
	buf.WriteString("</div>")

	return buf.String()
}

func handle2FA(w http.ResponseWriter, r *http.Request) {
	html := `
	<!DOCTYPE html>
	<html>
	<head>
		<title>VRChat 2FA</title>
	</head>
	<body>
		<h1>VRChat 2FA</h1>
		<form action="/verify2fa" method="post">
			<label for="code">Enter 2FA Code:</label><br>
			<input type="text" id="code" name="code"><br><br>
			<input type="submit" value="Verify">
		</form>
	</body>
	</html>
	`
	w.Write([]byte(html))
}

func handleVerify2FA(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	code := r.FormValue("code")

	twoFactorAuthReq := TwoFactorAuthRequest{
		Code: code,
	}

	jsonData, err := json.Marshal(twoFactorAuthReq)
	if err != nil {
		http.Error(w, "Error encoding JSON", http.StatusInternalServerError)
		return
	}

	client := &http.Client{}
	req, err := http.NewRequest("POST", "https://vrchat.com/api/1/auth/twofactorauth/emailotp/verify", bytes.NewBuffer(jsonData))
	if err != nil {
		http.Error(w, "Error creating request", http.StatusInternalServerError)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", useragent)

	// Forward cookies from client to API
	for _, cookie := range r.Cookies() {
		req.AddCookie(cookie)
	}

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Error making request", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Error reading response", http.StatusInternalServerError)
		return
	}

	// Store cookies from API response to client's browser
	for _, cookie := range resp.Cookies() {
		http.SetCookie(w, cookie)
	}

	// Print result and return code to terminal
	fmt.Printf("2FA Verification Status Code: %d\n", resp.StatusCode)
	fmt.Printf("2FA Verification Response Body: %s\n", string(body))

	// Return simple web page with the info
	result := fmt.Sprintf("2FA Verification Status Code: %d<br>Response Body: %s", resp.StatusCode, string(body))
	html := fmt.Sprintf(`
	<!DOCTYPE html>
	<html>
	<head>
		<title>VRChat 2FA Verification Result</title>
	</head>
	<body>
		<h1>VRChat 2FA Verification Result</h1>
		<pre>%s</pre>
	</body>
	</html>
	`, result)

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

func handleFriends(w http.ResponseWriter, r *http.Request) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", "https://vrchat.com/api/1/auth/user/friends?n=100", nil)
	if err != nil {
		http.Error(w, "Error creating request", http.StatusInternalServerError)
		return
	}

	// Forward cookies from client to API
	for _, cookie := range r.Cookies() {
		req.AddCookie(cookie)
	}
	req.Header.Set("User-Agent", useragent)
	//req.Header.Set("Cookie", fmt.Sprintf("auth=%s", authCookie))

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Error making request", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Error reading response", http.StatusInternalServerError)
		return
	}

	var friends []Friend
	err = json.Unmarshal(body, &friends)
	if err != nil {
		http.Error(w, "Error parsing JSON", http.StatusInternalServerError)
		return
	}

	tmpl := template.Must(template.New("friends").Parse(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VRChat Friends</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f0f0f0;
            margin: 0;
            padding: 20px;
        }
        .friends-container {
            display: flex;
            flex-wrap: wrap;
            justify-content: center;
        }
        .friend-box {
            background-color: white;
            border-radius: 10px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            margin: 10px;
            padding: 20px;
            width: 300px;
        }
        .friend-box img {
            width: 100%;
            height: auto;
            border-radius: 5px;
        }
        .friend-box h2 {
            margin-top: 10px;
            margin-bottom: 5px;
        }
        .friend-box p {
            margin: 5px 0;
        }
        .status {
            font-weight: bold;
        }
        .bio {
            font-style: italic;
        }
    </style>
</head>
<body>
    <h1>VRChat Friends</h1>
    <div class="friends-container">
        {{range .}}
			{{ if ne .Location "offline" }}
			<div class="friend-box">
				{{ if .ProfilePicOverrideThumbnail }}
					<img src="{{.ProfilePicOverrideThumbnail}}" alt="{{.DisplayName}}'s Avatar">
				{{ else }}
					<img src="{{.CurrentAvatarThumbnailImageUrl}}" alt="{{.DisplayName}}'s Avatar">
				{{ end }}
				<h2>{{.DisplayName}}</h2>
				<b>{{.Status}}</b> {{ if eq .Status "busy" }}
					🔴 <!-- Red Circle -->
				{{ else if eq .Status "ask me" }}
					🟠 <!-- Orange Circle -->
				{{ else if eq .Status "join me" }}
					🔵 <!-- Blue Circle -->
				{{ else if eq .Status "active" }}
					🟢 <!-- Green Circle -->
				{{ else }}
					⚪ <!-- Default Circle for any other status -->
				{{ end }}
				<p>{{.StatusDescription}}</p>
			</div>
			{{ end }}
        {{end}}
    </div>
</body>
</html>
`))

//<p class="bio">{{.Bio}}</p>

	err = tmpl.Execute(w, friends)
	if err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
	}
}

// <img src="{{.CurrentAvatarImageUrl}}" alt="{{.DisplayName}}'s Avatar">
// <img src="{{.CurrentAvatarThumbnailImageUrl}}" alt="{{.DisplayName}}'s Avatar">
// <img src="{{.ProfilePicOverride}}" alt="{{.DisplayName}}'s Avatar">
// <img src="{{.ProfilePicOverrideThumbnail}}" alt="{{.DisplayName}}'s Avatar">

func handleGroups(w http.ResponseWriter, r *http.Request) {
	var ck, err = r.Cookie("user_id")
	if err != nil {
		http.Error(w, "Error no user id cookie stored", http.StatusInternalServerError)
		return
	}

	var user_id = ck.Value

	var endpoint = fmt.Sprintf(`/users/%s/instances/groups/`, user_id)


	html := fmt.Sprintf(`
	<!DOCTYPE html>
	<html>
	<head>
		<title>VRChat handleGroups</title>
	</head>
	<body>
		%s
	</body>
	</html>
	`, user_id)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}
