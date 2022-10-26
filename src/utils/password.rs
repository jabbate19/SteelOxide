use crate::utils::user::UserInfo;
use rpassword::prompt_password;

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let password = prompt_password("Enter password for users: ").unwrap();
    for user in UserInfo::get_all_users() {
        user.change_password(&password);
    }
    Ok(())
}
