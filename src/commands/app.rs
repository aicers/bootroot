use crate::i18n::Messages;

pub(crate) fn run_app_add(messages: &Messages) {
    println!("{}", messages.not_implemented_app_add());
}

pub(crate) fn run_app_info(messages: &Messages) {
    println!("{}", messages.not_implemented_app_info());
}
