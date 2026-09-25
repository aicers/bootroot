//! Test support: checks an image reference bootroot runs against the
//! committed runtime image declaration, `deploy/runtime-images.json`.
//!
//! The declaration names the exact upstream registry images this
//! revision approves. Compose defaults are checked against it by
//! `scripts/validate-runtime-images.sh`; image references compiled into
//! the binaries — the `OpenBao` Agent sidecar image, the step-ca helper
//! image — are checked here, by the tests that own them, against the
//! value or argv production actually uses.
//!
//! Only `repository` and `tag` are read. The declaration's format
//! (schema, digests, versions, platforms) is the shell validator's to
//! check, and the digest never reaches a production reference: offline
//! installs run the archive-restored tag.
//!
//! The integration tests include this file by `#[path]` as well, so it
//! must not name anything from the `bootroot` binary crate.

use serde::Deserialize;

const DECLARATION: &str = include_str!("../deploy/runtime-images.json");
const SUPPORTED_SCHEMA: u64 = 1;
const DOCKER_HUB_DOMAIN: &str = "docker.io";
const DOCKER_HUB_LEGACY_DOMAIN: &str = "index.docker.io";
const DOCKER_HUB_OFFICIAL_NAMESPACE: &str = "library";

#[derive(Deserialize)]
struct Declaration {
    schema: u64,
    dependencies: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    dependency: String,
    repository: String,
    tag: String,
}

/// An image reference split into its fully qualified repository and tag.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ImageReference {
    pub(crate) repository: String,
    pub(crate) tag: Option<String>,
}

/// Splits `name[:tag][@digest]`, expanding Docker Hub shorthand.
///
/// A one-segment name gains `docker.io/library/`, an unqualified
/// multi-segment name gains `docker.io/`. A first segment naming a
/// registry host — dotted, carrying a port, or `localhost` — stays that
/// host and is never read as a Docker Hub namespace.
pub(crate) fn parse_image_reference(reference: &str) -> ImageReference {
    let name = reference.split('@').next().unwrap_or(reference);
    let last_slash = name.rfind('/');
    let (name, tag) = match name.rfind(':') {
        Some(colon) if last_slash.is_none_or(|slash| colon > slash) => {
            (&name[..colon], Some(name[colon + 1..].to_string()))
        }
        _ => (name, None),
    };
    ImageReference {
        repository: normalize_repository(name),
        tag,
    }
}

fn normalize_repository(name: &str) -> String {
    let (domain, remainder) = match name.split_once('/') {
        Some((first, rest))
            if first.contains('.') || first.contains(':') || first == "localhost" =>
        {
            let domain = if first == DOCKER_HUB_LEGACY_DOMAIN {
                DOCKER_HUB_DOMAIN
            } else {
                first
            };
            (domain, rest)
        }
        _ => (DOCKER_HUB_DOMAIN, name),
    };
    if domain == DOCKER_HUB_DOMAIN && !remainder.contains('/') {
        format!("{domain}/{DOCKER_HUB_OFFICIAL_NAMESPACE}/{remainder}")
    } else {
        format!("{domain}/{remainder}")
    }
}

/// Returns the declared `(repository, tag)` for `role`.
///
/// # Panics
///
/// Panics when the committed declaration does not parse, carries an
/// unsupported schema, or does not declare `role`.
pub(crate) fn declared_image(role: &str) -> (String, String) {
    let declaration: Declaration =
        serde_json::from_str(DECLARATION).expect("deploy/runtime-images.json must parse");
    assert_eq!(
        declaration.schema, SUPPORTED_SCHEMA,
        "deploy/runtime-images.json carries an unsupported schema"
    );
    let entry = declaration
        .dependencies
        .into_iter()
        .find(|entry| entry.dependency == role)
        .unwrap_or_else(|| panic!("deploy/runtime-images.json does not declare {role:?}"));
    (entry.repository, entry.tag)
}

/// Asserts that `image`, found at `source`, is the declared image for
/// `role`: the same canonical repository and the exact declared tag.
///
/// # Panics
///
/// Panics when the reference names another repository or tag, or
/// carries no tag at all.
pub(crate) fn assert_declared_image(role: &str, image: &str, source: &str) {
    let (repository, tag) = declared_image(role);
    let reference = parse_image_reference(image);
    assert_eq!(
        reference.repository, repository,
        "{source} runs {image:?}, whose repository differs from the declared {role:?} \
         image {repository}:{tag} in deploy/runtime-images.json"
    );
    assert_eq!(
        reference.tag.as_deref(),
        Some(tag.as_str()),
        "{source} runs {image:?}, whose tag differs from the declared {role:?} \
         image {repository}:{tag} in deploy/runtime-images.json"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(repository: &str, tag: Option<&str>) -> ImageReference {
        ImageReference {
            repository: repository.to_string(),
            tag: tag.map(str::to_string),
        }
    }

    #[test]
    fn a_one_segment_name_is_a_docker_hub_official_image() {
        assert_eq!(
            parse_image_reference("postgres:18.4"),
            reference("docker.io/library/postgres", Some("18.4"))
        );
    }

    #[test]
    fn an_unqualified_namespace_is_on_docker_hub() {
        assert_eq!(
            parse_image_reference("smallstep/step-ca:0.30.2"),
            reference("docker.io/smallstep/step-ca", Some("0.30.2"))
        );
    }

    #[test]
    fn qualified_docker_hub_spellings_normalize_alike() {
        let expected = reference("docker.io/library/postgres", Some("18.4"));
        assert_eq!(parse_image_reference("docker.io/postgres:18.4"), expected);
        assert_eq!(
            parse_image_reference("index.docker.io/library/postgres:18.4"),
            expected
        );
    }

    #[test]
    fn a_registry_host_is_never_a_docker_hub_namespace() {
        assert_eq!(
            parse_image_reference("registry.example.com/openbao/openbao:2.5.5"),
            reference("registry.example.com/openbao/openbao", Some("2.5.5"))
        );
        assert_eq!(
            parse_image_reference("localhost:5000/step-ca:0.30.2"),
            reference("localhost:5000/step-ca", Some("0.30.2"))
        );
        assert_eq!(
            parse_image_reference("localhost/step-ca"),
            reference("localhost/step-ca", None)
        );
    }

    #[test]
    fn a_digest_does_not_become_the_tag() {
        assert_eq!(
            parse_image_reference("postgres:18.4@sha256:abc"),
            reference("docker.io/library/postgres", Some("18.4"))
        );
        assert_eq!(
            parse_image_reference("postgres@sha256:abc"),
            reference("docker.io/library/postgres", None)
        );
    }

    #[test]
    #[should_panic(expected = "whose tag differs")]
    fn another_tag_is_rejected() {
        assert_declared_image("postgres", "postgres:99", "fixture");
    }

    #[test]
    #[should_panic(expected = "whose repository differs")]
    fn another_repository_is_rejected() {
        assert_declared_image(
            "openbao",
            "registry.example.com/openbao/openbao:2.5.5",
            "fixture",
        );
    }

    #[test]
    #[should_panic(expected = "does not declare")]
    fn an_undeclared_role_is_rejected() {
        assert_declared_image("prometheus", "prom/prometheus:v3.13.1", "fixture");
    }
}
