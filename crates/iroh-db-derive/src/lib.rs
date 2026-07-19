//! Derive macros for typed iroh-db records.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use proc_macro::TokenStream;
use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{format_ident, quote};
use syn::{
    Data, DeriveInput, Fields, GenericArgument, Ident, LitInt, LitStr, PathArguments, Type,
    parse_macro_input, spanned::Spanned as _,
};

/// Generates the stable schema, canonical record codec and typed field metadata.
#[proc_macro_derive(IrohRecord, attributes(iroh_db))]
pub fn derive_iroh_record(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

#[derive(Default)]
struct RecordAttrs {
    collection: Option<String>,
    version: Option<u32>,
}

#[derive(Default)]
struct FieldAttrs {
    id: bool,
    indexed: bool,
    field_id: Option<u32>,
}

struct FieldInfo {
    ident: Ident,
    ty: Type,
    field_id: u32,
    is_id: bool,
    indexed: bool,
    value_ty: Type,
    kind: Ident,
}

// Keeping validation and emitted fragments together makes diagnostic spans precise.
#[allow(clippy::too_many_lines)]
fn expand(input: DeriveInput) -> syn::Result<TokenStream2> {
    if !input.generics.params.is_empty() {
        return Err(syn::Error::new_spanned(
            input.generics,
            "IrohRecord does not support generic records; use a concrete durable schema type",
        ));
    }

    let attrs = parse_record_attrs(&input)?;
    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => &fields.named,
            Fields::Unnamed(_) | Fields::Unit => {
                return Err(syn::Error::new_spanned(
                    &input.ident,
                    "IrohRecord requires a struct with named fields",
                ));
            }
        },
        Data::Enum(_) | Data::Union(_) => {
            return Err(syn::Error::new_spanned(
                &input.ident,
                "IrohRecord can only be derived for structs",
            ));
        }
    };

    let mut infos: Vec<FieldInfo> = Vec::with_capacity(fields.len());
    let mut numeric_ids = BTreeMap::<u32, Span>::new();
    let mut record_id_index = None;
    for field in fields {
        let ident = field
            .ident
            .clone()
            .expect("named fields always carry identifiers");
        let field_attrs = parse_field_attrs(field)?;
        let field_id = field_attrs
            .field_id
            .unwrap_or_else(|| stable_field_id(&ident.to_string()));
        if field_id == 0 {
            return Err(syn::Error::new(
                ident.span(),
                "field_id 0 is reserved for record-level operations",
            ));
        }
        if let Some(previous) = numeric_ids.insert(field_id, ident.span()) {
            let mut error = syn::Error::new(
                ident.span(),
                format!("duplicate iroh-db field_id {field_id}"),
            );
            error.combine(syn::Error::new(previous, "first used by this field"));
            return Err(error);
        }

        let (kind, value_ty) = if field_attrs.id {
            if let Some(previous) = record_id_index.replace(infos.len()) {
                let mut error = syn::Error::new(ident.span(), "multiple #[iroh_db(id)] fields");
                error.combine(syn::Error::new(
                    infos[previous].ident.span(),
                    "first record ID is here",
                ));
                return Err(error);
            }
            (format_ident!("Immutable"), field.ty.clone())
        } else {
            replicated_type(&field.ty)?
        };

        infos.push(FieldInfo {
            ident,
            ty: field.ty.clone(),
            field_id,
            is_id: field_attrs.id,
            indexed: field_attrs.indexed,
            value_ty,
            kind,
        });
    }

    let id_index = record_id_index.ok_or_else(|| {
        syn::Error::new_spanned(
            &input.ident,
            "IrohRecord requires exactly one #[iroh_db(id)] field",
        )
    })?;
    if infos[id_index].indexed {
        return Err(syn::Error::new(
            infos[id_index].ident.span(),
            "the record ID is always indexed; remove #[iroh_db(index)]",
        ));
    }

    let core = core_path()?;
    let name = &input.ident;
    let collection = attrs.collection.unwrap_or_else(|| name.to_string());
    let collection = LitStr::new(&collection, name.span());
    let version = attrs.version.unwrap_or(1);
    let id_ident = &infos[id_index].ident;
    let id_ty = &infos[id_index].ty;

    let descriptors = infos.iter().map(|field| {
        let field_id = field.field_id;
        let field_name = LitStr::new(&field.ident.to_string(), field.ident.span());
        let kind = &field.kind;
        let value_ty = &field.value_ty;
        let indexed = field.indexed;
        let record_id = field.is_id;
        quote! {
            {
                let descriptor = #core::FieldDescriptor::new(
                    #field_id,
                    #field_name,
                    #core::CrdtKind::#kind,
                    stringify!(#value_ty),
                );
                let descriptor = if #indexed { descriptor.indexed() } else { descriptor };
                if #record_id { descriptor.record_id() } else { descriptor }
            }
        }
    });

    let encoders = infos.iter().map(|field| {
        let ident = &field.ident;
        let ty = &field.ty;
        let field_id = field.field_id;
        if field.is_id {
            quote! { (#field_id, <#ty as #core::RecordKey>::encode_key(&self.#ident)?) }
        } else {
            quote! { (#field_id, <#ty as #core::FieldState>::encode_state(&self.#ident)?) }
        }
    });

    let decoders = infos.iter().map(|field| {
        let ident = &field.ident;
        let ty = &field.ty;
        let field_id = field.field_id;
        if field.is_id {
            quote! { #ident: <#ty as #core::RecordKey>::decode_key(fields.required(#field_id)?)? }
        } else {
            quote! { #ident: <#ty as #core::FieldState>::decode_state(fields.required(#field_id)?)? }
        }
    });

    let constants = infos.iter().map(|field| {
        let ident = &field.ident;
        let field_id = field.field_id;
        let field_name = LitStr::new(&ident.to_string(), ident.span());
        let value_ty = &field.value_ty;
        let indexed = field.indexed || field.is_id;
        quote! {
            #[allow(non_upper_case_globals)]
            pub const #ident: #core::TypedField<Self, #value_ty> =
                #core::TypedField::new(#field_id, #field_name, #indexed);
        }
    });

    let value_extractors = infos.iter().map(|field| {
        let ident = &field.ident;
        let ty = &field.ty;
        let field_id = field.field_id;
        if field.is_id {
            quote! { #field_id => Ok(vec![<#ty as #core::RecordKey>::encode_key(&self.#ident)?]) }
        } else {
            quote! { #field_id => <#ty as #core::FieldState>::visible_values(&self.#ident) }
        }
    });

    let mergers = infos.iter().filter(|field| !field.is_id).map(|field| {
        let ident = &field.ident;
        let ty = &field.ty;
        quote! {
            <#ty as #core::FieldState>::merge_state(&mut self.#ident, &other.#ident)?;
        }
    });

    let causal_normalizers = infos.iter().filter(|field| !field.is_id).map(|field| {
        let ident = &field.ident;
        let ty = &field.ty;
        quote! {
            self.#ident = <#ty as #core::FieldState>::canonicalize_for_commit(
                &self.#ident,
                author,
                sequence,
                context,
                next_operation,
            )?;
        }
    });

    Ok(quote! {
        impl #core::IrohRecord for #name {
            type Id = #id_ty;

            fn schema() -> ::core::result::Result<#core::SchemaDescriptor, #core::RecordError> {
                Ok(#core::SchemaDescriptor::new(
                    #collection,
                    #version,
                    vec![#(#descriptors),*],
                )?)
            }

            fn id(&self) -> &Self::Id {
                &self.#id_ident
            }

            fn encode_record(&self) -> ::core::result::Result<Vec<u8>, #core::RecordError> {
                #core::encode_record_fields([#(#encoders),*])
            }

            fn decode_record(bytes: &[u8]) -> ::core::result::Result<Self, #core::RecordError> {
                let fields = #core::decode_record_fields(bytes)?;
                Ok(Self { #(#decoders),* })
            }

            fn field_values(
                &self,
                field_id: u32,
            ) -> ::core::result::Result<Vec<Vec<u8>>, #core::RecordError> {
                match field_id {
                    #(#value_extractors),*,
                    _ => Ok(Vec::new()),
                }
            }

            fn merge_record(&mut self, other: &Self) -> ::core::result::Result<(), #core::RecordError> {
                if self.record_id()? != other.record_id()? {
                    return Err(#core::RecordError::MergeUnavailable);
                }
                #(#mergers)*
                Ok(())
            }

            fn canonicalize_causality(
                &mut self,
                author: #core::AuthorId,
                sequence: u64,
                context: &#core::VersionVector,
                next_operation: &mut u32,
            ) -> ::core::result::Result<(), #core::RecordError> {
                #(#causal_normalizers)*
                Ok(())
            }
        }

        impl #name {
            #(#constants)*
        }
    })
}

fn parse_record_attrs(input: &DeriveInput) -> syn::Result<RecordAttrs> {
    let mut result = RecordAttrs::default();
    for attr in &input.attrs {
        if !attr.path().is_ident("iroh_db") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("collection") {
                if result.collection.is_some() {
                    return Err(meta.error("duplicate collection attribute"));
                }
                result.collection = Some(meta.value()?.parse::<LitStr>()?.value());
                Ok(())
            } else if meta.path.is_ident("version") {
                if result.version.is_some() {
                    return Err(meta.error("duplicate version attribute"));
                }
                result.version = Some(meta.value()?.parse::<LitInt>()?.base10_parse()?);
                Ok(())
            } else {
                Err(meta.error("unsupported iroh_db record attribute"))
            }
        })?;
    }
    Ok(result)
}

fn parse_field_attrs(field: &syn::Field) -> syn::Result<FieldAttrs> {
    let mut result = FieldAttrs::default();
    for attr in &field.attrs {
        if !attr.path().is_ident("iroh_db") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("id") {
                if result.id {
                    return Err(meta.error("duplicate id attribute"));
                }
                result.id = true;
                Ok(())
            } else if meta.path.is_ident("index") {
                if result.indexed {
                    return Err(meta.error("duplicate index attribute"));
                }
                result.indexed = true;
                Ok(())
            } else if meta.path.is_ident("field_id") {
                if result.field_id.is_some() {
                    return Err(meta.error("duplicate field_id attribute"));
                }
                result.field_id = Some(meta.value()?.parse::<LitInt>()?.base10_parse()?);
                Ok(())
            } else {
                Err(meta.error("unsupported iroh_db field attribute"))
            }
        })?;
    }
    Ok(result)
}

fn replicated_type(ty: &Type) -> syn::Result<(Ident, Type)> {
    let Type::Path(path) = ty else {
        return Err(syn::Error::new(
            ty.span(),
            "replicated fields must use a built-in iroh-db CRDT type",
        ));
    };
    let segment =
        path.path.segments.last().ok_or_else(|| {
            syn::Error::new(ty.span(), "replicated field type path cannot be empty")
        })?;
    let kind = segment.ident.to_string();
    if kind == "BlobRef" {
        if !matches!(segment.arguments, PathArguments::None) {
            return Err(syn::Error::new_spanned(
                &segment.arguments,
                "BlobRef does not accept a value type",
            ));
        }
        return Ok((format_ident!("Immutable"), ty.clone()));
    }
    if kind == "PnCounter" {
        if !matches!(segment.arguments, PathArguments::None) {
            return Err(syn::Error::new_spanned(
                &segment.arguments,
                "PnCounter does not accept a value type",
            ));
        }
        return Ok((segment.ident.clone(), syn::parse_quote!(i128)));
    }
    if !matches!(
        kind.as_str(),
        "Lww" | "OrSet" | "GrowOnlySet" | "MultiValue" | "Immutable" | "OrderedList"
    ) {
        return Err(syn::Error::new(
            ty.span(),
            "replicated fields must use Lww, OrSet, GrowOnlySet, PnCounter, MultiValue, Immutable, or OrderedList",
        ));
    }
    let PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return Err(syn::Error::new_spanned(
            &segment.ident,
            "this CRDT requires exactly one value type",
        ));
    };
    let mut types = arguments.args.iter().filter_map(|argument| match argument {
        GenericArgument::Type(ty) => Some(ty.clone()),
        _ => None,
    });
    let value_ty = types.next().ok_or_else(|| {
        syn::Error::new_spanned(arguments, "this CRDT requires exactly one value type")
    })?;
    if types.next().is_some() || arguments.args.len() != 1 {
        return Err(syn::Error::new_spanned(
            arguments,
            "this CRDT requires exactly one value type",
        ));
    }
    Ok((segment.ident.clone(), value_ty))
}

fn stable_field_id(name: &str) -> u32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"iroh-db/field/v1");
    hasher.update(name.as_bytes());
    let bytes: [u8; 4] = hasher.finalize().as_bytes()[..4]
        .try_into()
        .expect("a BLAKE3 digest always has four bytes");
    u32::from_be_bytes(bytes).max(1)
}

fn core_path() -> syn::Result<TokenStream2> {
    if let Ok(found) = crate_name("iroh-db") {
        return Ok(match found {
            FoundCrate::Itself => quote!(::iroh_db::__private::core),
            FoundCrate::Name(name) => {
                let name = format_ident!("{}", name.replace('-', "_"));
                quote!(::#name::__private::core)
            }
        });
    }
    match crate_name("iroh-db-core") {
        Ok(FoundCrate::Itself) => Ok(quote!(crate)),
        Ok(FoundCrate::Name(name)) => {
            let name = format_ident!("{}", name.replace('-', "_"));
            Ok(quote!(::#name))
        }
        Err(error) => Err(syn::Error::new(
            Span::call_site(),
            format!("IrohRecord needs the iroh-db or iroh-db-core crate: {error}"),
        )),
    }
}
