package main

import (
	"html/template"
	"path/filepath"
	"sync"
)

var (
	templateDir = "./templates"
	templates   = map[string]*template.Template{}
	tmplMu      sync.RWMutex
)

// LoadTemplate loads and caches a template by name.
func LoadTemplate(name string) (*template.Template, error) {
	tmplMu.RLock()
	t, ok := templates[name]
	tmplMu.RUnlock()
	if ok {
		return t, nil
	}
	tmplMu.Lock()
	defer tmplMu.Unlock()
	tmplPath := filepath.Join(templateDir, name+".html")
	tmpl, err := template.ParseFiles(tmplPath)
	if err != nil {
		return nil, err
	}
	templates[name] = tmpl
	return tmpl, nil
}
