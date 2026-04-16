const ssoConfigurationPage = {
  pluginUniqueId: "505ce9d1-d916-42fa-86ca-673ef241d7df",
  loadConfiguration: (page) => {
    ApiClient.getPluginConfiguration(ssoConfigurationPage.pluginUniqueId).then(
      (config) => {
        ssoConfigurationPage.populateProviders(page, config.OidConfigs);
      },
    );

    const folder_container = page.querySelector("#EnabledFolders");
    ssoConfigurationPage.populateFolders(folder_container);
  },
  populateProviders: (page, providers) => {
    // Clear providers in case there are out of date ones
    page
      .querySelector("#selectProvider")
      .querySelectorAll("option")
      .forEach((option) => {
        option.remove();
      });

    // Add providers as options for the selector

    Object.keys(providers).forEach((provider_name) => {
      var choice = new Option(provider_name, provider_name);

      page.querySelector("#selectProvider").appendChild(choice);
    });
  },
  populateEnabledFolders: (folder_list, container) => {
    container.querySelectorAll(".folder-checkbox").forEach((e) => {
      e.checked = folder_list.includes(e.getAttribute("data-id"));
    });
  },
  serializeEnabledFolders: (container) => {
    return [...container.querySelectorAll(".folder-checkbox")]
      .filter((e) => e.checked)
      .map((e) => {
        return e.getAttribute("data-id");
      });
  },
  populateFolders: (container) => {
    return ApiClient.getJSON(
      ApiClient.getUrl("Library/MediaFolders", {
        IsHidden: false,
      }),
    ).then((folders) => {
      ssoConfigurationPage._populateFolders(container, folders);
    });
  },
  /*
  container: html element
  folders.Items: array of objects, with .Id & .Name
  */
  _populateFolders: (container, folders) => {
    container
      .querySelectorAll(".emby-checkbox-label")
      .forEach((e) => e.remove());

    const checkboxes = folders.Items.map((folder) => {
      var out = document.createElement("label");

      var checkbox = document.createElement("input");
      checkbox.setAttribute("is", "emby-checkbox");
      checkbox.classList.add("folder-checkbox", "chkFolder");
      checkbox.setAttribute("data-id", folder.Id);
      checkbox.type = "checkbox";

      var span = document.createElement("span");
      span.textContent = folder.Name;

      out.appendChild(checkbox);
      out.appendChild(span);

      return out;
    });

    checkboxes.forEach((e) => {
      container.appendChild(e);
    });
  },

  populateRoleMappings: (folder_role_mappings, container) => {
    container
      .querySelectorAll(".sso-role-mapping-container")
      .forEach((e) => e.remove());

    const mapping_elements = folder_role_mappings.map((mapping) => {
      var elem = document.createElement("div");

      elem.classList.add("sso-role-mapping-container");
      elem.innerHTML = `
      <label
        class="inputLabel inputLabelUnfocused sso-role-mapping-input-label" 
      >Role:</label>
      <div class="listItem">
        <input
          is="emby-input"
          required=""
          type="text"
          class="listItemBody sso-role-mapping-name"
        />
        <button
          type="button"
          is="paper-icon-button-light"
          class="listItemButton sso-remove-role-mapping"
        >
          <span class="material-icons remove_circle" aria-hidden="true"></span>
        </button> 
      </div> 
      <div
        class="checkboxList paperList sso-folder-list"
      ></div>
      `;

      var checklist = elem.querySelector(".sso-folder-list");
      const enabled_folders = mapping["Folders"];

      ssoConfigurationPage
        .populateFolders(checklist)
        .then(() =>
          ssoConfigurationPage.populateEnabledFolders(
            enabled_folders,
            checklist,
          ),
        );

      elem.querySelector(".sso-role-mapping-name").value = mapping["Role"];
      elem
        .querySelector(".sso-remove-role-mapping")
        .addEventListener(
          "click",
          ssoConfigurationPage.handleRoleMappingRemove,
        );

      return elem;
    });

    mapping_elements.forEach((e) => container.appendChild(e));
  },
  serializeRoleMappings: (container) => {
    var out = [];
    const roles = [
      ...container.querySelectorAll(".sso-role-mapping-container"),
    ].forEach((elem) => {
      const role = elem.querySelector(".sso-role-mapping-name").value;
      const checklist = elem.querySelector(".sso-folder-list");

      out.push({
        Role: role,
        Folders: ssoConfigurationPage.serializeEnabledFolders(checklist),
      });
    });

    return out;
  },
  handleRoleMappingRemove: (evt) => {
    const targeted_mapping = evt.target.closest(".sso-role-mapping-container");
    targeted_mapping.remove();
  },
  listArgumentsByType: (page) => {
    const json_class = ".sso-json";
    const toggle_class = ".sso-toggle";
    const text_class = ".sso-text";
    const text_list_class = ".sso-line-list";

    const folder_list_fields = ["EnabledFolders"];
    const role_map_fields = ["FolderRoleMapping"];

    const oidc_form = page.querySelector("#sso-new-oidc-provider");

    const text_fields = [...oidc_form.querySelectorAll(text_class)].map(
      (e) => e.id,
    );

    const json_fields = [...oidc_form.querySelectorAll(json_class)].map(
      (e) => e.id,
    );

    const text_list_fields = [
      ...oidc_form.querySelectorAll(text_list_class),
    ].map((e) => e.id);

    const check_fields = [...oidc_form.querySelectorAll(toggle_class)].map(
      (e) => e.id,
    );

    const output = {
      json_fields,
      text_list_fields,
      text_fields,
      check_fields,
      folder_list_fields,
      role_map_fields,
    };

    return output;
  },
  fillTextList: (text_list, element) => {
    // text_list is an array of strings
    // element is an input element
    const val = text_list.join("\r\n");
    element.value = val;
  },
  parseTextList: (element) => {
    // Return the parsed text list
    var out = element.value
      .split("\n")
      .map((e) => e.trim())
      .filter((e) => e);
    return out;
  },
  loadProvider: (page, provider_name) => {
    ApiClient.getPluginConfiguration(ssoConfigurationPage.pluginUniqueId).then(
      (config) => {
        var provider = config.OidConfigs[provider_name] || {};

        const form_elements = ssoConfigurationPage.listArgumentsByType(page);

        page.querySelector("#OidProviderName").value = provider_name;

        form_elements.text_fields.forEach((id) => {
          if (provider[id]) page.querySelector("#" + id).value = provider[id];
        });

        form_elements.json_fields.forEach((id) => {
          if (provider[id])
            page.querySelector("#" + id).value = JSON.stringify(provider[id]);
        });

        form_elements.text_list_fields.forEach((id) => {
          if (provider[id])
            ssoConfigurationPage.fillTextList(
              provider[id],
              page.querySelector("#" + id),
            );
        });

        form_elements.folder_list_fields.forEach((id) => {
          if (provider[id]) {
            ssoConfigurationPage.populateEnabledFolders(
              provider[id],
              page.querySelector(`#${id}`),
            );
          }
        });

        form_elements.check_fields.forEach((id) => {
          if (provider[id]) page.querySelector("#" + id).checked = provider[id];
        });

        form_elements.role_map_fields.forEach((id) => {
          const elem = page.querySelector(`#${id}`);
          if (provider[id])
            ssoConfigurationPage.populateRoleMappings(provider[id], elem);
        });

        // Load canonical links for this provider
        ssoConfigurationPage.loadCanonicalLinks(page, provider_name);
      },
    );
  },
  deleteProvider: (page, provider_name) => {
    if (
      !window.confirm(
        `Are you sure you want to delete the provider ${provider_name}?`,
      )
    ) {
      return;
    }
    return new Promise((resolve) => {
      ApiClient.getPluginConfiguration(
        ssoConfigurationPage.pluginUniqueId,
      ).then((config) => {
        if (!config.OidConfigs.hasOwnProperty(provider_name)) {
          resolve();
          return;
        }

        delete config.OidConfigs[provider_name];
        ApiClient.updatePluginConfiguration(
          ssoConfigurationPage.pluginUniqueId,
          config,
        ).then(function (result) {
          Dashboard.processPluginConfigurationUpdateResult(result);
          ssoConfigurationPage.loadConfiguration(page);

          Dashboard.alert("Provider removed");

          resolve();
        });
      });
    });
  },
  saveProvider: (page, provider_name) => {
    return new Promise((resolve) => {
      const form_elements = ssoConfigurationPage.listArgumentsByType(page);

      ApiClient.getPluginConfiguration(
        ssoConfigurationPage.pluginUniqueId,
      ).then((config) => {
        var current_config = {};
        if (config.OidConfigs.hasOwnProperty(provider_name)) {
          current_config = config.OidConfigs[provider_name];
        }

        form_elements.text_fields.forEach((id) => {
          const value = page.querySelector("#" + id).value;
          if (value) {
            current_config[id] = page.querySelector("#" + id).value;
          } else {
            current_config[id] = null;
          }
        });

        form_elements.json_fields.forEach((id) => {
          const value = page.querySelector("#" + id).value;
          if (value) {
            current_config[id] = JSON.parse(value);
          } else {
            current_config[id] = null;
          }
        });

        form_elements.check_fields.forEach((id) => {
          current_config[id] = page.querySelector("#" + id).checked;
        });

        form_elements.text_list_fields.forEach((id) => {
          current_config[id] = ssoConfigurationPage.parseTextList(
            page.querySelector("#" + id),
          );
        });

        form_elements.folder_list_fields.forEach((id) => {
          const elem = page.querySelector(`#${id}`);
          current_config[id] =
            ssoConfigurationPage.serializeEnabledFolders(elem);
        });

        form_elements.role_map_fields.forEach((id) => {
          const elem = page.querySelector(`#${id}`);
          current_config[id] = ssoConfigurationPage.serializeRoleMappings(elem);
        });

        config.OidConfigs[provider_name] = current_config;

        ApiClient.updatePluginConfiguration(
          ssoConfigurationPage.pluginUniqueId,
          config,
        ).then(function (result) {
          Dashboard.processPluginConfigurationUpdateResult(result);
          ssoConfigurationPage.loadConfiguration(page);
          ssoConfigurationPage.loadProvider(page, provider_name);

          page.querySelector("#selectProvider").value = provider_name;
          Dashboard.alert("Settings saved.");
          resolve();
        });
      });
    });
  },
  addTextAreaStyle: (view) => {
    var style = document.createElement("link");
    style.rel = "stylesheet";
    style.href =
      ApiClient.getUrl("web/configurationpage") + "?name=SSO-Auth.css";
    view.appendChild(style);
  },
  populateJellyfinUsers: (page) => {
    return ApiClient.getJSON(ApiClient.getUrl("Users")).then((users) => {
      const select = page.querySelector("#sso-new-link-jellyfin-user");
      select.innerHTML = "";
      users.forEach((user) => {
        var option = document.createElement("option");
        option.value = user.Id;
        option.textContent = user.Name + " (" + user.Id + ")";
        select.appendChild(option);
      });
      return users;
    });
  },
  loadCanonicalLinks: (page, provider_name) => {
    if (!provider_name) return;
    ApiClient.getPluginConfiguration(ssoConfigurationPage.pluginUniqueId).then(
      (config) => {
        var provider = config.OidConfigs[provider_name] || {};
        var links = provider.CanonicalLinks || {};
        ssoConfigurationPage.renderCanonicalLinks(page, links, provider_name);
      },
    );
    ssoConfigurationPage.populateJellyfinUsers(page);
  },
  renderCanonicalLinks: (page, links, provider_name) => {
    const container = page.querySelector("#sso-canonical-links-list");
    container.innerHTML = "";

    var keys = Object.keys(links);
    if (keys.length === 0) {
      var empty = document.createElement("p");
      empty.textContent = "No user mappings configured for this provider.";
      empty.style.fontStyle = "italic";
      container.appendChild(empty);
      return;
    }

    var table = document.createElement("table");
    table.style.width = "100%";
    table.style.borderCollapse = "collapse";

    var thead = document.createElement("thead");
    var headerRow = document.createElement("tr");
    ["SSO Username", "Jellyfin User ID", ""].forEach((text) => {
      var th = document.createElement("th");
      th.textContent = text;
      th.style.textAlign = "left";
      th.style.padding = "0.5em";
      th.style.borderBottom = "1px solid #444";
      headerRow.appendChild(th);
    });
    thead.appendChild(headerRow);
    table.appendChild(thead);

    var tbody = document.createElement("tbody");
    keys.forEach((ssoUsername) => {
      var row = document.createElement("tr");

      var tdSso = document.createElement("td");
      tdSso.textContent = ssoUsername;
      tdSso.style.padding = "0.5em";
      row.appendChild(tdSso);

      var tdJf = document.createElement("td");
      tdJf.textContent = links[ssoUsername];
      tdJf.style.padding = "0.5em";
      tdJf.style.fontFamily = "monospace";
      tdJf.style.fontSize = "0.85em";
      row.appendChild(tdJf);

      var tdAction = document.createElement("td");
      tdAction.style.padding = "0.5em";
      var removeBtn = document.createElement("button");
      removeBtn.setAttribute("is", "emby-button");
      removeBtn.classList.add("raised", "button-delete", "emby-button");
      removeBtn.textContent = "Remove";
      removeBtn.addEventListener("click", () => {
        if (
          window.confirm("Remove mapping for SSO user '" + ssoUsername + "'?")
        ) {
          ssoConfigurationPage.removeCanonicalLink(
            page,
            provider_name,
            ssoUsername,
          );
        }
      });
      tdAction.appendChild(removeBtn);
      row.appendChild(tdAction);

      tbody.appendChild(row);
    });
    table.appendChild(tbody);
    container.appendChild(table);
  },
  addCanonicalLink: (page, provider_name, ssoUsername, jellyfinUserId) => {
    if (!provider_name || !ssoUsername || !jellyfinUserId) {
      Dashboard.alert(
        "Please fill in both the SSO username and select a Jellyfin user.",
      );
      return;
    }
    ApiClient.getPluginConfiguration(ssoConfigurationPage.pluginUniqueId).then(
      (config) => {
        if (!config.OidConfigs[provider_name]) {
          Dashboard.alert("Provider not found. Load a provider first.");
          return;
        }
        if (!config.OidConfigs[provider_name].CanonicalLinks) {
          config.OidConfigs[provider_name].CanonicalLinks = {};
        }
        config.OidConfigs[provider_name].CanonicalLinks[ssoUsername] =
          jellyfinUserId;
        ApiClient.updatePluginConfiguration(
          ssoConfigurationPage.pluginUniqueId,
          config,
        ).then(() => {
          Dashboard.alert("Mapping added.");
          ssoConfigurationPage.loadCanonicalLinks(page, provider_name);
        });
      },
    );
  },
  removeCanonicalLink: (page, provider_name, ssoUsername) => {
    ApiClient.getPluginConfiguration(ssoConfigurationPage.pluginUniqueId).then(
      (config) => {
        if (
          config.OidConfigs[provider_name] &&
          config.OidConfigs[provider_name].CanonicalLinks
        ) {
          delete config.OidConfigs[provider_name].CanonicalLinks[ssoUsername];
          ApiClient.updatePluginConfiguration(
            ssoConfigurationPage.pluginUniqueId,
            config,
          ).then(() => {
            Dashboard.alert("Mapping removed.");
            ssoConfigurationPage.loadCanonicalLinks(page, provider_name);
          });
        }
      },
    );
  },
};

export default function (view) {
  ssoConfigurationPage.addTextAreaStyle(view);
  ssoConfigurationPage.loadConfiguration(view);

  ssoConfigurationPage.listArgumentsByType(view);

  view.querySelector("#SaveProvider").addEventListener("click", (e) => {
    const target_provider = view.querySelector("#OidProviderName").value;

    ssoConfigurationPage.saveProvider(view, target_provider);

    e.preventDefault();
    return false;
  });

  view.querySelector("#LoadProvider").addEventListener("click", (e) => {
    const target_provider = view.querySelector("#selectProvider").value;

    ssoConfigurationPage.loadProvider(view, target_provider);

    e.preventDefault();
    return false;
  });

  view.querySelector("#DeleteProvider").addEventListener("click", (e) => {
    const target_provider = view.querySelector("#selectProvider").value;

    ssoConfigurationPage.deleteProvider(view, target_provider);

    e.preventDefault();
    return false;
  });

  view.querySelector("#AddRoleMapping").addEventListener("click", (e) => {
    const container = view.querySelector("#FolderRoleMapping");
    const current_mappings =
      ssoConfigurationPage.serializeRoleMappings(container);
    current_mappings.push({ Role: "", Folders: [] });
    console.log(current_mappings);
    ssoConfigurationPage.populateRoleMappings(current_mappings, container);
  });

  view.querySelector("#AddCanonicalLink").addEventListener("click", (e) => {
    const provider_name = view.querySelector("#OidProviderName").value;
    const ssoUsername = view
      .querySelector("#sso-new-link-sso-username")
      .value.trim();
    const jellyfinUserId = view.querySelector(
      "#sso-new-link-jellyfin-user",
    ).value;

    ssoConfigurationPage.addCanonicalLink(
      view,
      provider_name,
      ssoUsername,
      jellyfinUserId,
    );

    view.querySelector("#sso-new-link-sso-username").value = "";
    e.preventDefault();
    return false;
  });

  // Populate Jellyfin users dropdown on page load
  ssoConfigurationPage.populateJellyfinUsers(view);

  view.querySelector("#sso-self-service-link").href =
    ApiClient.getUrl("/SSOViews/linking");
}
