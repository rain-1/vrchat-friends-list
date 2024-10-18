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
	"sort"
	"strings"
	"time"
)

type AuthResponse struct {
	RequiresTwoFactorAuth []string `json:"requiresTwoFactorAuth"`
}

type VRChatUser struct {
	ID                            string   `json:"id"`
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
}

type TwoFactorAuthRequest struct {
	Code string `json:"code"`
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

type ResponseBody struct {
	FetchedAt string     `json:"fetchedAt"`
	Instances []Instance `json:"instances"`
}

type Instance struct {
	ID        string   `json:"id"`
	OwnerID   string   `json:"ownerId"`
	Name      string   `json:"name"`
	WorldID   string   `json:"worldId"`
	Type      string   `json:"type"`
	GroupAccessType string `json:"groupAccessType"`
	UserCount int      `json:"userCount"`
	Capacity  int      `json:"capacity"`
	Tags      []string `json:"tags"`
	World     World    `json:"world"`
	Region    string   `json:"photonRegion"`
}

type World struct {
	Name              string `json:"name"`
	AuthorName        string `json:"authorName"`
	Description       string `json:"description"`
	ThumbnailImageUrl string `json:"thumbnailImageUrl"`
}

const useragent = "rain-1 vrchat-friend-list 1"

func main() {
	http.HandleFunc("/", handleMain)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/auth", handleAuth)
	http.HandleFunc("/2fa", handle2FA)
	http.HandleFunc("/verify2fa", handleVerify2FA)
	http.HandleFunc("/friends", handleFriends)
	http.HandleFunc("/groups", handleGroups)
	fmt.Println("Server is running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleMain(w http.ResponseWriter, r *http.Request) {
	_, err := r.Cookie("auth")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	html := `
	<!DOCTYPE html>
	<html>
	<head>
		<title>VRChat Dashboard</title>
	</head>
	<body>
		<h1>VRChat Dashboard</h1>
		<ul>
			<li><a href="/friends">View Friends</a></li>
			<li><a href="/groups">View Groups</a></li>
		</ul>
	</body>
	</html>
	`
	w.Write([]byte(html))
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
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
	username := r.FormValue("username")
	password := r.FormValue("password")

	auth := base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(username) + ":" + url.QueryEscape(password)))

	resp, body, err := makeRequest(r, "GET", "https://vrchat.com/api/1/auth/user", nil, map[string]string{"Authorization": "Basic " + auth})
	if err != nil {
		http.Error(w, "Error making request", http.StatusInternalServerError)
		return
	}

	for _, cookie := range resp.Cookies() {
		http.SetCookie(w, cookie)
	}

	var authResp AuthResponse
	err = json.Unmarshal(body, &authResp)
	if err == nil && len(authResp.RequiresTwoFactorAuth) > 0 {
		http.SetCookie(w, &http.Cookie{
			Name:  "2fa_type",
			Value: authResp.RequiresTwoFactorAuth[0],
			Path:  "/",
		})
		http.Redirect(w, r, "/2fa", http.StatusSeeOther)
		return
	}

	var user VRChatUser
	err = json.Unmarshal(body, &user)
	if err != nil {
		http.Error(w, "Error parsing JSON response", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "user_id",
		Value:   user.ID,
		Expires: time.Now().Add(30 * 24 * time.Hour),
		Path:    "/",
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handle2FA(w http.ResponseWriter, r *http.Request) {
	twoFAType, err := r.Cookie("2fa_type")
	if err != nil {
		http.Error(w, "No 2FA type specified", http.StatusBadRequest)
		return
	}

	html := fmt.Sprintf(`
	<!DOCTYPE html>
	<html>
	<head>
		<title>VRChat 2FA</title>
	</head>
	<body>
		<h1>VRChat 2FA (%s)</h1>
		<form action="/verify2fa" method="post">
			<input type="hidden" name="type" value="%s">
			<label for="code">Enter 2FA Code:</label><br>
			<input type="text" id="code" name="code"><br><br>
			<input type="submit" value="Verify">
		</form>
	</body>
	</html>
	`, twoFAType.Value, twoFAType.Value)
	w.Write([]byte(html))
}

func handleVerify2FA(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	twoFAType := r.FormValue("type")
	code := r.FormValue("code")

	twoFactorAuthReq := TwoFactorAuthRequest{
		Code: code,
	}

	jsonData, err := json.Marshal(twoFactorAuthReq)
	if err != nil {
		http.Error(w, "Error encoding JSON", http.StatusInternalServerError)
		return
	}

	endpoint := fmt.Sprintf("https://vrchat.com/api/1/auth/twofactorauth/%s/verify", twoFAType)
	resp, _, err := makeRequest(r, "POST", endpoint, bytes.NewBuffer(jsonData), map[string]string{"Content-Type": "application/json"})
	if err != nil {
		http.Error(w, "Error making request", http.StatusInternalServerError)
		return
	}

	for _, cookie := range resp.Cookies() {
		http.SetCookie(w, cookie)
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleFriends(w http.ResponseWriter, r *http.Request) {
	_, body, err := makeRequest(r, "GET", "https://vrchat.com/api/1/auth/user/friends?n=100", nil, nil)
	if err != nil {
		http.Error(w, "Error making request", http.StatusInternalServerError)
		return
	}

	var friends []Friend
	err = json.Unmarshal(body, &friends)
	if err != nil {
		http.Error(w, "Error parsing JSON", http.StatusInternalServerError)
		return
	}

	statusMap := map[string]int{
		"join me": 0,
		"active":  1,
		"ask me":  2,
		"busy":    3,
	}
	sort.Slice(friends, func(i, j int) bool {
		statusI, existsI := statusMap[strings.ToLower(friends[i].Status)]
		statusJ, existsJ := statusMap[strings.ToLower(friends[j].Status)]
		
		if !existsI {
			statusI = 99
		}
		if !existsJ {
			statusJ = 99
		}

		return statusI < statusJ
	})	

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
					🔴
				{{ else if eq .Status "ask me" }}
					🟠
				{{ else if eq .Status "join me" }}
					🔵
				{{ else if eq .Status "active" }}
					🟢
				{{ else }}
					⚪
				{{ end }}
				<p>{{.StatusDescription}}</p>
			</div>
			{{ end }}
        {{end}}
    </div>
</body>
</html>
`))

	err = tmpl.Execute(w, friends)
	if err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
	}
}

func handleGroups(w http.ResponseWriter, r *http.Request) {
	userID, err := r.Cookie("user_id")
	if err != nil {
		http.Error(w, "Error no user id cookie stored", http.StatusInternalServerError)
		return
	}
	
	endpoint := fmt.Sprintf("https://vrchat.com/api/1/users/%s/instances/groups/", userID.Value)
	_, body, err := makeRequest(r, "GET", endpoint, nil, nil)
	if err != nil {
		http.Error(w, "Error making request", http.StatusInternalServerError)
		return
	}

	fmt.Println(string(body))
	//{"error":"The endpoint you're looking for is not implemented by our system.","status_code":404}

	var responseBody ResponseBody
	err = json.Unmarshal(body, &responseBody)
	if err != nil {
		log.Fatalf("Error parsing JSON: %v", err)
	}

	const htmlTemplate = `
	<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>VRChat Instances</title>
		<style>
			table {
				border-collapse: collapse;
				width: 100%;
			}
			th, td {
				border: 1px solid #ddd;
				padding: 8px;
				text-align: left;
			}
			th {
				background-color: #f2f2f2;
			}
		</style>
	</head>
	<body>
        <h1>VRChat Instances</h1>
    <table>
        <tr>
            <th>Thumbnail</th>
            <th>World Name</th>
            <th>World Author</th>
            <th>Type</th>
            <th>Users</th>
            <th>Description</th>
        </tr>
        {{range .Instances}}
        <tr>
            <td><img src="{{.World.ThumbnailImageUrl}}" alt="{{.World.Name}} thumbnail" class="thumbnail"></td>
            <td>{{.OwnerID}}</td>
            <td>{{.World.Name}} @ {{.Region}}</td>
            <td>{{.World.AuthorName}}</td>
            <td>{{.GroupAccessType}}</td>
            <td>{{.UserCount}} / {{.Capacity}}</td>
            <td>{{.World.Description}}</td>
        </tr>
        {{end}}
    </table>

	</body>
	</html>
	`
	
	tmpl, err := template.New("instances").Funcs(template.FuncMap{
		"join": strings.Join,
	}).Parse(htmlTemplate)
	if err != nil {
		log.Fatalf("Error creating template: %v", err)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err = tmpl.Execute(w, responseBody)
	if err != nil {
		log.Fatalf("Error generating HTML: %v", err)
	}
}

func makeRequest(r *http.Request, method, url string, body *bytes.Buffer, headers map[string]string) (*http.Response, []byte, error) {
	client := &http.Client{}
	var req *http.Request
	var err error

	if body != nil {
		req, err = http.NewRequest(method, url, body)
	} else {
		req, err = http.NewRequest(method, url, nil)
	}

	if err != nil {
		return nil, nil, err
	}

	req.Header.Set("User-Agent", useragent)
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	for _, cookie := range r.Cookies() {
		req.AddCookie(cookie)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	return resp, responseBody, nil
}
