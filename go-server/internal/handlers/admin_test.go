package handlers

import (
	"testing"
)

func TestOpsTaskList(t *testing.T) {
	tasks := opsTaskList()

	expectedOrder := []string{
		"css-cohesion",
		"feature-inventory",
		"scientific-colors",
		"render-diagrams",
		"figma-bundle",
		"figma-verify",
		"miro-sync",
		"full-pipeline",
	}

	if len(tasks) != len(expectedOrder) {
		t.Fatalf("expected %d tasks, got %d", len(expectedOrder), len(tasks))
	}

	for i, expected := range expectedOrder {
		if tasks[i].ID != expected {
			t.Errorf("task[%d].ID = %q, want %q", i, tasks[i].ID, expected)
		}
	}
}

func TestOpsTaskList_Labels(t *testing.T) {
	tasks := opsTaskList()
	for _, task := range tasks {
		if task.Label == "" {
			t.Errorf("task %q has empty label", task.ID)
		}
		if task.Icon == "" {
			t.Errorf("task %q has empty icon", task.ID)
		}
		if task.Command == "" {
			t.Errorf("task %q has empty command", task.ID)
		}
		if len(task.Args) == 0 {
			t.Errorf("task %q has empty args", task.ID)
		}
	}
}

func TestOpsWhitelist_AllEntriesPresent(t *testing.T) {
	expectedIDs := []string{
		"css-cohesion",
		"feature-inventory",
		"scientific-colors",
		"render-diagrams",
		"figma-bundle",
		"figma-verify",
		"miro-sync",
		"full-pipeline",
	}
	for _, id := range expectedIDs {
		if _, ok := opsWhitelist[id]; !ok {
			t.Errorf("expected opsWhitelist to contain %q", id)
		}
	}
}

func TestOpsWhitelist_Commands(t *testing.T) {
	nodeCommands := []string{"css-cohesion", "feature-inventory", "scientific-colors", "figma-bundle", "figma-verify", "miro-sync", "full-pipeline"}
	for _, id := range nodeCommands {
		task := opsWhitelist[id]
		if task.Command != "node" {
			t.Errorf("task %q command = %q, want 'node'", id, task.Command)
		}
	}

	renderTask := opsWhitelist["render-diagrams"]
	if renderTask.Command != "bash" {
		t.Errorf("render-diagrams command = %q, want 'bash'", renderTask.Command)
	}
}
