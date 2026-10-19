export const UserRolesEnum = {
  ADMIN: "admin", //Enum = fixed options ki list
  //Agar kisi field mein sirf kuch specific values hi allowed hain, toh hum enum use karte hain.

  PROJECT_ADMIN: "project_admin",
  MEMBER: "member", 
};
export const AvailableUserRole = Object.values(UserRolesEnum); //Object.values() = ye function enum ke andar ke values ko array mein convert kar deta hai.we can send object as well as array. But in this case, we want to send array of values. So we use Object.values() function to convert enum into array of values.

export const taskStatusEnum = {
  TODO: "todo",
  IN_PROGRESS: "in_progress",
  DONE: "done",
};
export const AvailableTaskStatus = Object.values(taskStatusEnum);

export const ProjectStatusEnum = {
  UNKNOWN: "Unknown",
  PLANNING: "Planning",
  IN_PROGRESS: "In Progress",
  COMPLETED: "Completed",
  ON_HOLD: "On Hold",
};
export const AvailableProjectStatus = Object.values(ProjectStatusEnum);

export const TaskPriorityEnum = {
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  URGENT: "urgent",
};
export const AvailableTaskPriority = Object.values(TaskPriorityEnum);

export const ActivityActionEnum = {
  PROJECT_CREATED: "project_created",
  PROJECT_UPDATED: "project_updated",
  MEMBER_ADDED: "member_added",
  MEMBER_ROLE_UPDATED: "member_role_updated",
  MEMBER_REMOVED: "member_removed",
  TASK_CREATED: "task_created",
  TASK_UPDATED: "task_updated",
  TASK_STATUS_CHANGED: "task_status_changed",
  TASK_DELETED: "task_deleted",
  SUBTASK_CREATED: "subtask_created",
  SUBTASK_STATUS_CHANGED: "subtask_status_changed",
  SUBTASK_DELETED: "subtask_deleted",
  NOTE_CREATED: "note_created",
  NOTE_UPDATED: "note_updated",
  NOTE_DELETED: "note_deleted",
  ATTACHMENT_UPLOADED: "attachment_uploaded",
};
export const AvailableActivityActions = Object.values(ActivityActionEnum);

export const ActivityResourceEnum = {
  PROJECT: "project",
  MEMBER: "member",
  TASK: "task",
  SUBTASK: "subtask",
  NOTE: "note",
  ATTACHMENT: "attachment",
};
export const AvailableActivityResources = Object.values(ActivityResourceEnum);
