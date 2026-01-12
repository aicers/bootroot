use crate::i18n::Messages;

pub(crate) fn run_verify(messages: &Messages) {
    println!("{}", messages.not_implemented_verify());
}
