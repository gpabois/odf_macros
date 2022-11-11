extern crate darling;
extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use syn::{parse_macro_input, DeriveInput, parse::Parser, AttributeArgs};
use quote::{quote, ToTokens};
use darling::FromMeta;

fn capitalize_first_letter(s: &str) -> String {
    s[0..1].to_uppercase() + &s[1..]
}

#[derive(FromMeta, Debug)]
struct ElementDescriptor {
    namespace: syn::Path,
    name: String,

    #[darling(multiple)]
    attributes: Vec<ElementAttribute>,
    
    children: Option<syn::Path>
}

#[derive(FromMeta, Debug)]
struct ElementAttribute {
    name: syn::Ident,
    att_type: syn::Ident,
    prefix: String
}

fn add_fields_to_struct(mut ast: DeriveInput, fields: &[TokenStream2]) -> TokenStream2 {
    match &mut ast.data {
        syn::Data::Struct(ref mut struct_data) => {     
            match &mut struct_data.fields {
                syn::Fields::Named(named_fields) => {
                    fields.iter().for_each(|f|
                        named_fields.named.push(
                            syn::Field::parse_named.parse2(f.clone()).unwrap()
                        )
                    );
                }   
                _ => {
                    ()
                }
            }                
        },
        _ => panic!("Not a struct")
    };
    

    quote!(#ast).into()
}

fn build_opendocumentnode_impl_for_element(struct_name: &syn::Ident, descriptor: &ElementDescriptor) -> TokenStream2 {
    let namespace = &descriptor.namespace;
    let name = &descriptor.name;

    let from_element_impl = build_from_element_impl_for_element(descriptor);

    quote! {
        impl OpenDocumentElement for #struct_name 
        {
            fn is_element(el: &minidom::Element) -> bool {
                el.is(#name, #namespace)
            }

            #from_element_impl
        }
    }
}

fn build_from_element_impl_for_element(descriptor: &ElementDescriptor) -> TokenStream2 {
    let mut into_element_body: Vec<TokenStream2> = vec![];
    
    if let Some(t) = &descriptor.children {
        into_element_body.push(
            quote!{            
                children: el.children().map(|c| {
                    #t :: from_element(c)?
                }).collect()
            }
        );
    }
    
    descriptor.attributes.iter().for_each(|att| {
        let attr_name = &att.name;
        let attr_type = &att.att_type;
        let s_attr_name = attr_name.to_string();

        into_element_body.push(quote! {
            #attr_name: #attr_type :: from_str(el.attr(#s_attr_name).unwrap())?
        });
    });

    quote!{
        fn from_element(el: &minidom::Element) -> crate::Result<Self> {
            Ok(
                Self {
                    #(#into_element_body),
                    *
                }
            )
        }
    }
}

fn build_into_element_impl_for_element(struct_name: &syn::Ident, descriptor: &ElementDescriptor) -> TokenStream2 {
    let namespace = &descriptor.namespace;
    let name = &descriptor.name;

    // Build From<minidom::Element> impl for 
    let mut from_element_body: Vec<TokenStream2> = vec![];
    from_element_body.push(quote!{
        let mut builder = minidom::Element::builder(#name, #namespace);
    });

    if let Some(_) = &descriptor.children {
        from_element_body.push(
            quote!{            
                builder = self.children.into_iter().fold(builder, |builder, el| {
                    builder.append(el)
                });
            }
        );
    }

    descriptor.attributes.iter().for_each(|att| {
        let attr_name = &att.name;
        let s_attr_name = attr_name.to_string();
        from_element_body.push(quote! {
            builder = builder.attr(#s_attr_name, self. #attr_name);
        });
    });

    from_element_body.push(quote!{builder.build()});

    quote!{
        impl Into<minidom::Element> for #struct_name {
            fn into(self) -> minidom::Element {
                #(#from_element_body)*
            }
        }
    }
}

#[proc_macro_attribute]
pub fn define_element(args: TokenStream, input: TokenStream) -> TokenStream
{
    let struct_ast = parse_macro_input!(input as DeriveInput);
    let attr_args = parse_macro_input!(args as AttributeArgs);

    match ElementDescriptor::from_list(&attr_args)
    {
        Ok(descriptor) => {
            let mut fields: Vec<TokenStream2> = vec![];

            // Ajout du champs enfant dans le struct
            if let Some(c) = &descriptor.children {
                fields.push(quote! {pub children: Vec<#c>});
            }

            // On crée les champs par rapport aux attributs attendus
            fields = descriptor.attributes.iter().fold(fields, |mut fields, attr| {
                let attr_name = &attr.name;
                let attr_type = &attr.att_type;
                
                fields.push(
                    quote!{
                        pub #attr_name: #attr_type
                    }
                );

                fields
            });
            
            let ast = add_fields_to_struct(struct_ast.clone(), &fields);

            let struct_name = struct_ast.ident.clone();

            // Implement OpenDocumentElement
            let open_document_element_impl = build_opendocumentnode_impl_for_element(&struct_name, &descriptor);
            let from_impl = build_into_element_impl_for_element(&struct_name, &descriptor);

            quote! {
                #ast
                #open_document_element_impl
                #from_impl
            }.into()
        },
        Err(e) => panic!("Erreur lors du parsing des arguments: {}", e)
    }
}

/// Permet de définir les types d'enfants que peut avoir un noeud (appliqué à un Enum)
#[proc_macro_attribute]
pub fn define_child_elements(args: TokenStream, input: TokenStream) -> TokenStream
{
    let args = parse_macro_input!(args as syn::AttributeArgs);
    let mut types: Vec<syn::Path> = vec![];
    
    // Get the types
    args.iter().for_each(|nested_meta| {
        if let syn::NestedMeta::Meta(meta) = nested_meta {
            if let syn::Meta::Path(p) = meta {
                types.push(p.clone());
            }
        }
    });

    let mut enum_ast = parse_macro_input!(input as DeriveInput);
    let enum_id = enum_ast.ident.clone();

    match &mut enum_ast.data {
        syn::Data::Enum(ref mut enum_data) => {
            types.iter().for_each(|t| {
                let arg_name = t.into_token_stream()
                .to_string()
                .split("::")
                .map(capitalize_first_letter)
                .collect::<Vec<String>>()
                .join("")
                .replace(" ", "");
                
                let type_name: String = t.into_token_stream().to_string();

                enum_data.variants.push(
                    syn::parse_str::<syn::Variant>(&format!("{}({})", arg_name, type_name)).unwrap_or_else(
                        |t|
                        panic!("{}", arg_name)
                    )
                );
            })
        },
        _ => panic!("`define_child_elements` is only possible on enum.")
    };

    let mut from_element_body = quote! {};
    let mut to_element_body = quote!{};
    
    to_element_body = types.iter().fold(to_element_body, |ast, t| {
        let arg_name = syn::parse_str::<syn::Ident>(t.into_token_stream()
        .to_string()
        .split("::")
        .map(capitalize_first_letter)
        .collect::<Vec<String>>()
        .join("")
        .replace(" ", "")
        .as_str()).unwrap();

        quote!{
            #ast
            Self:: #arg_name (t) => {
                t.into()
            },
        }
    });

    from_element_body = types.iter().fold(from_element_body, |ast, t| {
        quote!{
            #ast

            if #t::is_element(element) {
                return Ok(Self::from(#t::from_element(element)?));
            }
            
        }
    });

    from_element_body = quote! {
        #from_element_body
        panic!("element is not a valid child element")
    };
    
    let from_element = quote!(
        impl OpenDocumentElement for #enum_id {
            fn is_element(element: &minidom::Element) -> bool {
                true
            }
            
            fn from_element(element: &minidom::Element) -> crate::Result<Self> {
                #from_element_body
            }
        }
    );

    let to_element = quote!(
        impl Into<minidom::Element> for #enum_id {
            fn into(self) -> minidom::Element {
                match self {
                    #to_element_body
                }
            }
        }
    );

    let ast = types.iter().fold(enum_ast.to_token_stream(), |ast, t| {
        let arg_name = syn::parse_str::<syn::Ident>(t.into_token_stream()
        .to_string()
        .split("::")
        .map(capitalize_first_letter)
        .collect::<Vec<String>>()
        .join("")
        .replace(" ", "")
        .as_str()).unwrap();

        quote!{
            #ast    

            impl From<#t> for #enum_id {
                fn from(c: #t) -> Self {
                    #enum_id :: #arg_name (c)
                }
            }
        }
    });

    return quote!(#ast #from_element #to_element).into();

}

#[proc_macro_attribute]
pub fn header_attrs(_args: TokenStream, input: TokenStream) -> TokenStream
{
    let ast = parse_macro_input!(input as DeriveInput); 
    
    add_fields_to_struct(ast, &[
        quote!{pub outline_level: u8},
        quote!{pub restart_numbering: bool},
        quote!{pub start_value: u8},
        quote!{pub is_list_header: bool},
        quote!{pub number: String}
    ]).into()
}

#[proc_macro_attribute]
pub fn paragraph_attrs(_args: TokenStream, input: TokenStream) -> TokenStream
{
    let ast = parse_macro_input!(input as DeriveInput);
    add_fields_to_struct(ast, &[
        quote!{pub style_name: Option<String>},
        quote!{pub class_names: Option<String>},
        quote!{pub cond_style_name: Option<String>},
        quote!{pub id: Option<String>}        
    ]).into()
}