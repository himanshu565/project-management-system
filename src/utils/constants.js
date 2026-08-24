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
