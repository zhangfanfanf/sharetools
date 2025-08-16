package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"embed"
)

const (
	uploadDir          = "./shared_files" // 文件存储目录
	defaultMaxUploadMB = 200              // 默认最大上传文件大小(MB)
	port               = ":8000"          // 服务器端口
	sessionName        = "fileshare_session"
	sessionKey         = "authenticated"
	cookieExpireHours  = 2 // Cookie过期时间(小时)
	configFile         = "./fileshare_config.json"
)

var (
	username    = "0" // 初始用户名
	password    = "0" // 初始密码
	maxUploadMB = defaultMaxUploadMB
	templates   *template.Template
)

type Config struct {
	MaxUploadMB int `json:"max_upload_mb"`
}

type FileInfo struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mod_time"`
	IsDir   bool      `json:"is_dir"`
}

type TemplateData struct {
	Authenticated   bool
	MaxUploadMB     int
	ShowSettings    bool
	CurrentUsername string
	Message         string
	Success         bool
}
//go:embed templates/*
var templateFS embed.FS
func main() {
	// 加载配置
	loadConfig()

	// 初始化模板
	initTemplates()

	// 确保共享目录存在
	if err := os.MkdirAll(uploadDir, 0o755); err != nil {
		log.Fatalf("无法创建共享目录: %v", err)
	}

	// 设置路由
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/upload", authMiddleware(uploadHandler))
	http.HandleFunc("/download/", downloadHandler)
	http.HandleFunc("/list", listHandler)
	http.HandleFunc("/delete/", authMiddleware(deleteHandler))
	http.HandleFunc("/preview/", previewHandler)
	http.HandleFunc("/settings", authMiddleware(settingsHandler))
	http.HandleFunc("/update-config", authMiddleware(updateConfigHandler))

	// 静态文件服务
	fs := http.FileServer(http.Dir(uploadDir))
	http.Handle("/files/", http.StripPrefix("/files/", fs))

	ip, err := getLocalIP()
	if err != nil {
		log.Printf("获取本机IP失败: %v, 使用localhost代替", err)
		ip = "localhost"
	}

	log.Printf("文件共享服务器已启动，访问 http://%s%s", ip, port)
	log.Printf("共享目录: %s", uploadDir)
	log.Printf("当前最大上传限制: %d MB", maxUploadMB)
	log.Fatal(http.ListenAndServe(port, nil))
}

func loadConfig() {
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		// 如果配置文件不存在，使用默认值
		maxUploadMB = defaultMaxUploadMB
		saveConfig()
		return
	}

	file, err := os.ReadFile(configFile)
	if err != nil {
		log.Printf("读取配置文件失败: %v, 使用默认值", err)
		maxUploadMB = defaultMaxUploadMB
		return
	}

	var config Config
	if err := json.Unmarshal(file, &config); err != nil {
		log.Printf("解析配置文件失败: %v, 使用默认值", err)
		maxUploadMB = defaultMaxUploadMB
		return
	}

	if config.MaxUploadMB > 0 {
		maxUploadMB = config.MaxUploadMB
	} else {
		maxUploadMB = defaultMaxUploadMB
	}
}

func saveConfig() {
	config := Config{
		MaxUploadMB: maxUploadMB,
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		log.Printf("序列化配置失败: %v", err)
		return
	}

	if err := os.WriteFile(configFile, data, 0o644); err != nil {
		log.Printf("写入配置文件失败: %v", err)
	}
}

func updateConfigHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "只允许POST方法", http.StatusMethodNotAllowed)
		return
	}

	newMaxMBStr := r.FormValue("max_upload_mb")
	newMaxMB, err := strconv.Atoi(newMaxMBStr)
	if err != nil || newMaxMB <= 0 {
		http.Error(w, "无效的上传大小限制", http.StatusBadRequest)
		return
	}

	maxUploadMB = newMaxMB
	saveConfig()

	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func initTemplates() {
	// 
	var err error
	templates, err = template.New("").ParseFS(templateFS, "templates/*.html")
	if err != nil {
		log.Fatalf("初始化模板失败: %v", err)
	}
}

func getLocalIP() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), nil
			}
		}
	}
	return "", fmt.Errorf("no non-loopback IPv4 address found")
}

func renderTemplate(w http.ResponseWriter, name string, data TemplateData) {
	err := templates.ExecuteTemplate(w, name, data)
	if err != nil {
		log.Printf("渲染模板 %s 出错: %v", name, err)
		http.Error(w, "页面渲染错误", http.StatusInternalServerError)
	}
}

func settingsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		data := TemplateData{
			CurrentUsername: username,
			Authenticated:   true,
			MaxUploadMB:     maxUploadMB,
		}
		renderTemplate(w, "settings.html", data)
		return
	}

	if r.Method == "POST" {
		r.ParseForm()
		currentPassword := r.FormValue("currentPassword")
		newUsername := strings.TrimSpace(r.FormValue("newUsername"))
		newPassword := r.FormValue("newPassword")
		confirmPassword := r.FormValue("confirmPassword")
		resetRequested := r.FormValue("resetUsername") == "1"

		// 验证当前密码
		passMatch := subtle.ConstantTimeCompare([]byte(currentPassword), []byte(password)) == 1
		if !passMatch {
			data := TemplateData{
				CurrentUsername: username,
				Message:         "当前密码不正确",
				Success:         false,
				Authenticated:   true,
				MaxUploadMB:     maxUploadMB,
			}
			renderTemplate(w, "settings.html", data)
			return
		}

		// 处理重置请求
		if resetRequested {
			username = "0"
			password = "0"
			data := TemplateData{
				CurrentUsername: username,
				Message:         "已重置为默认用户名和密码",
				Success:         true,
				Authenticated:   true,
				MaxUploadMB:     maxUploadMB,
			}
			renderTemplate(w, "settings.html", data)
			return
		}

		// 处理用户名更改
		if newUsername != "" {
			if len(newUsername) < 3 {
				data := TemplateData{
					CurrentUsername: username,
					Message:         "用户名至少需要3个字符",
					Success:         false,
					Authenticated:   true,
					MaxUploadMB:     maxUploadMB,
				}
				renderTemplate(w, "settings.html", data)
				return
			}
			username = newUsername
		}

		// 处理密码更改
		if newPassword != "" {
			if newPassword != confirmPassword {
				data := TemplateData{
					CurrentUsername: username,
					Message:         "新密码不匹配",
					Success:         false,
					Authenticated:   true,
					MaxUploadMB:     maxUploadMB,
				}
				renderTemplate(w, "settings.html", data)
				return
			}
			if len(newPassword) < 4 {
				data := TemplateData{
					CurrentUsername: username,
					Message:         "密码至少需要4个字符",
					Success:         false,
					Authenticated:   true,
					MaxUploadMB:     maxUploadMB,
				}
				renderTemplate(w, "settings.html", data)
				return
			}
			password = newPassword
		}

		data := TemplateData{
			CurrentUsername: username,
			Message:         "设置已保存",
			Success:         true,
			Authenticated:   true,
			MaxUploadMB:     maxUploadMB,
		}
		renderTemplate(w, "settings.html", data)
	}
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := r.Cookie(sessionName)
		if err != nil || session == nil || session.Value != sessionKey {
			http.Error(w, "请先登录", http.StatusUnauthorized)
			return
		}

		if !session.Expires.IsZero() && session.Expires.Before(time.Now()) {
			http.SetCookie(w, &http.Cookie{
				Name:     sessionName,
				Value:    "",
				Path:     "/",
				Expires:  time.Unix(0, 0),
				HttpOnly: true,
			})
			http.Error(w, "登录已过期，请重新登录", http.StatusUnauthorized)
			return
		}

		if !session.Expires.IsZero() {
			updatedCookie := *session
			updatedCookie.Expires = time.Now().Add(cookieExpireHours * time.Hour)
			http.SetCookie(w, &updatedCookie)
		}

		next(w, r)
	}
}

func isAuthenticated(r *http.Request) bool {
	session, err := r.Cookie(sessionName)
	if err != nil || session == nil || session.Value != sessionKey {
		return false
	}

	if !session.Expires.IsZero() && session.Expires.Before(time.Now()) {
		return false
	}

	return true
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		data := TemplateData{
			Authenticated: isAuthenticated(r),
		}
		renderTemplate(w, "login.html", data)
		return
	}

	if r.Method == "POST" {
		user := r.FormValue("username")
		pass := r.FormValue("password")
		remember := r.FormValue("remember") == "on"

		userMatch := subtle.ConstantTimeCompare([]byte(user), []byte(username)) == 1
		passMatch := subtle.ConstantTimeCompare([]byte(pass), []byte(password)) == 1

		if userMatch && passMatch {
			cookie := &http.Cookie{
				Name:     sessionName,
				Value:    sessionKey,
				Path:     "/",
				HttpOnly: true,
				Secure:   false,
			}

			if remember {
				cookie.Expires = time.Now().Add(cookieExpireHours * time.Hour)
			}

			http.SetCookie(w, cookie)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func previewHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "只允许GET方法", http.StatusMethodNotAllowed)
		return
	}

	filename := strings.TrimPrefix(r.URL.Path, "/preview/")
	if filename == "" {
		http.Error(w, "需要指定文件名", http.StatusBadRequest)
		return
	}

	filename, err := urlPathUnescape(filename)
	if err != nil {
		http.Error(w, "无效的文件名", http.StatusBadRequest)
		return
	}

	filePath := filepath.Join(uploadDir, filename)

	info, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
		} else {
			http.Error(w, "无法访问文件", http.StatusInternalServerError)
		}
		return
	}

	if info.IsDir() {
		http.Error(w, "不能预览目录", http.StatusBadRequest)
		return
	}

	ext := strings.ToLower(filepath.Ext(filename))
	imageTypes := map[string]string{
		".jpg":  "image/jpeg",
		".jpeg": "image/jpeg",
		".png":  "image/png",
		".gif":  "image/gif",
		".bmp":  "image/bmp",
		".webp": "image/webp",
	}

	contentType, isImage := imageTypes[ext]
	if !isImage {
		http.Error(w, "文件不是可预览的图片类型", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
	http.ServeFile(w, r, filePath)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	data := TemplateData{
		Authenticated: isAuthenticated(r),
		MaxUploadMB:   maxUploadMB,
		ShowSettings:  isAuthenticated(r),
	}
	renderTemplate(w, "index.html", data)
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "只允许POST方法", http.StatusMethodNotAllowed)
		return
	}

	// 将maxUploadMB转换为int64后再移位
	maxSize := int64(maxUploadMB) << 20

	// 限制上传大小
	r.Body = http.MaxBytesReader(w, r.Body, maxSize)
	if err := r.ParseMultipartForm(maxSize); err != nil {
		http.Error(w, fmt.Sprintf("文件太大，最大允许%dMB", maxUploadMB), http.StatusBadRequest)
		return
	}

	// 获取所有上传的文件
	files := r.MultipartForm.File["files"]
	if len(files) == 0 {
		http.Error(w, "没有选择文件", http.StatusBadRequest)
		return
	}

	var uploadedFiles []string
	var uploadErrors []string

	// 处理每个文件
	for _, fileHeader := range files {
		file, err := fileHeader.Open()
		if err != nil {
			uploadErrors = append(uploadErrors, fmt.Sprintf("无法打开文件 %s: %v", fileHeader.Filename, err))
			continue
		}

		// 创建目标文件
		dstPath := filepath.Join(uploadDir, filepath.Base(fileHeader.Filename))
		dst, err := os.Create(dstPath)
		if err != nil {
			uploadErrors = append(uploadErrors, fmt.Sprintf("无法创建文件 %s: %v", fileHeader.Filename, err))
			file.Close()
			continue
		}

		// 复制文件内容
		if _, err := io.Copy(dst, file); err != nil {
			uploadErrors = append(uploadErrors, fmt.Sprintf("写入文件 %s 失败: %v", fileHeader.Filename, err))
		} else {
			uploadedFiles = append(uploadedFiles, fileHeader.Filename)
		}

		file.Close()
		dst.Close()
	}

	// 返回上传结果
	if len(uploadErrors) > 0 {
		response := fmt.Sprintf("部分文件上传失败:\n%s\n成功上传的文件: %v", strings.Join(uploadErrors, "\n"), uploadedFiles)
		http.Error(w, response, http.StatusPartialContent)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "只允许GET方法", http.StatusMethodNotAllowed)
		return
	}

	filename := strings.TrimPrefix(r.URL.Path, "/download/")
	if filename == "" {
		http.Error(w, "需要指定文件名", http.StatusBadRequest)
		return
	}

	filename, err := urlPathUnescape(filename)
	if err != nil {
		http.Error(w, "无效的文件名", http.StatusBadRequest)
		return
	}

	filePath := filepath.Join(uploadDir, filename)

	info, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
		} else {
			http.Error(w, "无法访问文件", http.StatusInternalServerError)
		}
		return
	}

	if info.IsDir() {
		http.Error(w, "不能下载目录", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
	http.ServeFile(w, r, filePath)
}

func listHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "只允许GET方法", http.StatusMethodNotAllowed)
		return
	}

	files, err := os.ReadDir(uploadDir)
	if err != nil {
		http.Error(w, "无法读取目录: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var fileInfos []FileInfo
	for _, file := range files {
		info, err := file.Info()
		if err != nil {
			continue
		}

		fileInfos = append(fileInfos, FileInfo{
			Name:    file.Name(),
			Size:    info.Size(),
			ModTime: info.ModTime(),
			IsDir:   file.IsDir(),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(fileInfos)
}

func deleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		http.Error(w, "只允许DELETE方法", http.StatusMethodNotAllowed)
		return
	}

	filename := strings.TrimPrefix(r.URL.Path, "/delete/")
	if filename == "" {
		http.Error(w, "需要指定文件名", http.StatusBadRequest)
		return
	}

	filename, err := urlPathUnescape(filename)
	if err != nil {
		http.Error(w, "无效的文件名", http.StatusBadRequest)
		return
	}

	filePath := filepath.Join(uploadDir, filename)

	_, err = os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
		} else {
			http.Error(w, "无法访问文件", http.StatusInternalServerError)
		}
		return
	}

	if err := os.Remove(filePath); err != nil {
		http.Error(w, "删除文件失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func urlPathUnescape(path string) (string, error) {
	return strings.ReplaceAll(path, "%20", " "), nil
}
