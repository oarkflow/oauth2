package main

import "html/template"

// --- Update loginTmpl to include CSRF token in form ---

var loginTmpl = template.Must(template.New("login").Parse(`
<!DOCTYPE html>
<html>
<head>
	<title>Login</title>
	<style>
		body { font-family: sans-serif; background: #f7f7f7; }
		.form-box { background: #fff; padding: 2em; margin: 2em auto; max-width: 400px; border-radius: 8px; box-shadow: 0 2px 8px #ccc; }
		.error { color: #b00; }
		.token { word-break: break-all; background: #eee; padding: 0.5em; }
	</style>
	<script>
	function onProviderChange() {
		var method = document.getElementById('method').value;
		document.getElementById('username-row').style.display = (method === 'password') ? '' : 'none';
		document.getElementById('password-row').style.display = (method === 'password') ? '' : 'none';
		document.getElementById('apikey-row').style.display = (method === 'apikey') ? '' : 'none';
		document.getElementById('token-row').style.display = (['oauth2','google','clerk','cognito'].includes(method)) ? '' : 'none';
		document.getElementById('totp-row').style.display = (method === 'totp') ? '' : 'none';
		document.getElementById('mfa-row').style.display = (['mfa','2fa'].includes(method)) ? '' : 'none';
	}
	</script>
</head>
<body>
	<div class="form-box">
		<h2>Login</h2>
		{{if .Error}}<div class="error">{{.Error}}</div>{{end}}
		{{if .Token}}
			<div>Login successful! JWT:</div>
			<div class="token">{{.Token}}</div>
			<br>
			<form method="POST" action="/logout">
				<input type="hidden" name="session_token" value="{{.SessionToken}}">
				<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
				<button type="submit">Logout</button>
			</form>
			<br>
			<a href="/change-password">Change Password</a>
		{{else}}
		<form method="POST" autocomplete="off">
			<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
			<label for="method">Provider:</label>
			<select name="method" id="method" onchange="onProviderChange()">
				<option value="password">Password</option>
				<option value="apikey">API Key</option>
				<option value="cognito">AWS Cognito</option>
				<option value="oauth2">OAuth2 (Generic)</option>
				<option value="google">Google OAuth2</option>
				<option value="clerk">Clerk</option>
				<option value="totp">TOTP</option>
				<option value="mfa">MultiDevice MFA</option>
				<option value="2fa">2FA</option>
			</select>
			<div id="username-row">
				<label>Username: <input type="text" name="username" autocomplete="username"></label>
			</div>
			<div id="password-row">
				<label>Password: <input type="password" name="password" autocomplete="current-password"></label>
			</div>
			<div id="apikey-row" style="display:none">
				<label>API Key: <input type="text" name="apikey"></label>
			</div>
			<div id="token-row" style="display:none">
				<label>Token: <input type="text" name="token"></label>
			</div>
			<div id="totp-row" style="display:none">
				<label>TOTP Code: <input type="text" name="totp"></label>
			</div>
			<div id="mfa-row" style="display:none">
				<label>MFA/2FA Code: <input type="text" name="mfa"></label>
			</div>
			<br>
			<button type="submit">Login</button>
		</form>
		<a href="/forgot-password">Forgot Password?</a>
		<script>onProviderChange();</script>
		{{end}}
	</div>
</body>
</html>
`))

// Add templates for forgot/reset/change password
var forgotTmpl = template.Must(template.New("forgot").Parse(`
<!DOCTYPE html>
<html>
<head><title>Forgot Password</title></head>
<body>
	<div class="form-box">
		<h2>Forgot Password</h2>
		{{if .Error}}<div class="error">{{.Error}}</div>{{end}}
		{{if .ResetToken}}
			<div>Reset token (for demo): <span class="token">{{.ResetToken}}</span></div>
			<a href="/reset-password">Reset Password</a>
		{{else}}
		<form method="POST">
			<label>Email: <input type="email" name="email"></label>
			<button type="submit">Send Reset Link</button>
		</form>
		{{end}}
	</div>
</body>
</html>
`))

var resetTmpl = template.Must(template.New("reset").Parse(`
<!DOCTYPE html>
<html>
<head><title>Reset Password</title></head>
<body>
	<div class="form-box">
		<h2>Reset Password</h2>
		{{if .Error}}<div class="error">{{.Error}}</div>{{end}}
		{{if .Success}}
			<div>Password reset successful. <a href="/login">Login</a></div>
		{{else}}
		<form method="POST">
			<label>Reset Token: <input type="text" name="token"></label><br>
			<label>New Password: <input type="password" name="password"></label><br>
			<button type="submit">Reset Password</button>
		</form>
		{{end}}
	</div>
</body>
</html>
`))

var changeTmpl = template.Must(template.New("change").Parse(`
<!DOCTYPE html>
<html>
<head><title>Change Password</title></head>
<body>
	<div class="form-box">
		<h2>Change Password</h2>
		{{if .Error}}<div class="error">{{.Error}}</div>{{end}}
		{{if .Success}}
			<div>Password changed. Please <a href="/login">login</a> again.</div>
		{{else}}
		<form method="POST">
			<label>Session Token: <input type="text" name="session_token"></label><br>
			<label>Old Password: <input type="password" name="old_password"></label><br>
			<label>New Password: <input type="password" name="new_password"></label><br>
			<button type="submit">Change Password</button>
		</form>
		{{end}}
	</div>
</body>
</html>
`))

// --- Account Lockout & Exponential Backoff ---
