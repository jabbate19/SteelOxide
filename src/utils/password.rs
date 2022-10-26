use rpassword::prompt_password;
use crate::utils::user::UserInfo;

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let password = prompt_password("Enter password for users: ").unwrap();
    for user in UserInfo::get_all_users() {
        user.change_password(&password);
    }
    Ok(())
}