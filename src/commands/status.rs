use crate::i18n::Messages;

pub(crate) fn run_status(messages: &Messages) {
    println!("{}", messages.not_implemented_status());
}
